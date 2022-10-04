#!/bin/bash
# Copyright 2021 Nathan (Blaise) Bruer
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.W
set -euxo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# If set to "1", will create a crontab entry to upload a snapshot daily.
# This requires write permission to `s3://public-blockchain-snapshots`.
# You may also set this through an environmental variable at startup.
# SHOULD_AUTO_UPLOAD_SNAPSHOT="0"

function safe_wait() {
  BACKGROUND_PIDS=( $(jobs -p) )
  for PID in "${BACKGROUND_PIDS[@]}"; do
    wait -f $PID
  done
}

# Utility function that will ensure one function with specific name will on system wide.
# This will only have any effect if all other scripts use the same function.
function mutex_function() {
  local function_name="$1"
  set -euxo pipefail

  # Ensure only one instance of this function is running on entire system.
  (
    flock -x $fd
    $function_name
  ) {fd}>/tmp/$function_name.lock
}

function install_prereq() {
  set -euxo pipefail
  # Basic installs.
  apt update
  DEBIAN_FRONTEND=noninteractive apt install -y zfsutils-linux unzip pv clang-12 make jq python3-boto3 super cmake
  # Use clang as our compiler by default if needed.
  ln -s $(which clang-12) /usr/bin/cc || true
  snap install --classic go

  if ! cargo --version 2>&1 >/dev/null ; then
    # Install cargo.
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash /dev/stdin -y
    . "$HOME/.cargo/env"
  fi
}

function setup_drives() {
  set -euxo pipefail
  if zfs list tank ; then
    return # Our drives are probably already setup.
  fi
  # Creates a new pool with the default device.
  DEVICES=( $(lsblk --fs --json | jq -r '.blockdevices[] | select(.children == null and .fstype == null) | .name') )
  DEVICES_FULLNAME=()
  for DEVICE in "${DEVICES[@]}"; do
    DEVICES_FULLNAME+=("/dev/$DEVICE")
  done
  zpool create -o ashift=12 tank "${DEVICES_FULLNAME[@]}"
  # The root tank dataset does not get mounted.
  zfs set mountpoint=none tank

  # Configures ZFS to be slightly more optimal for our use case.
  zfs set compression=lz4 tank
  # Note: You might be able to get better erigon performance by changing this to 4k.
  zfs set recordsize=128k tank
  zfs set sync=disabled tank
  zfs set redundant_metadata=most tank
  zfs set atime=off tank
  zfs set logbias=throughput tank

  # By creating a swap it won't hurt much unless it's running on a small instance.
  # Under rare cases erigon might want to use an insane amount of ram (like if parlia database is
  # missing). This will allow us to at least get beyond that point. Measuring shows it only uses
  # about 48gb of ram when this happens. The vast majority of the time the swap will not be used.
  zfs create -s -V 48G -b $(getconf PAGESIZE) \
    -o compression=zle \
    -o sync=always \
    -o primarycache=metadata \
    -o secondarycache=none \
    tank/swap
  sleep 3 # It takes a moment for our zvol to be created.
  mkswap -f /dev/zvol/tank/swap
  swapon /dev/zvol/tank/swap

  # Set zfs's arc to 4GB. Erigon uses mmap() to map files into memory which is a cache system itself.
  echo 4147483648 > /sys/module/zfs/parameters/zfs_arc_max
}

function install_zstd() {
  set -euxo pipefail
  if pzstd --help ; then
    return # pzstd is already installed.
  fi
  # Download, setup and install zstd v1.5.2.
  # We use an upgraded version rather than what ubuntu uses because
  # 1.5.0+ greatly improved performance (3-5x faster for compression/decompression).
  mkdir -p /zstd
  cd /zstd
  wget -q -O- https://github.com/facebook/zstd/releases/download/v1.5.2/zstd-1.5.2.tar.gz | tar xzf -
  cd /zstd/zstd-1.5.2
  CC=clang-12 CXX=clang++-12 CFLAGS="-O3" make zstd -j$(nproc)
  ln -s /zstd/zstd-1.5.2/zstd /usr/bin/zstd || true
  cd /zstd/zstd-1.5.2/contrib/pzstd
  CC=clang-12 CXX=clang++-12 CFLAGS="-O3" make pzstd -j$(nproc)
  rm -rf /usr/bin/pzstd || true
  ln -s /zstd/zstd-1.5.2/contrib/pzstd/pzstd /usr/bin/pzstd
}

function install_aws_cli() {
  set -euxo pipefail
  if aws --version ; then
    return # Aws cli already installed.
  fi
  temp_dir=$(mktemp -d)
  cd $temp_dir
  curl "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  ./aws/install
  cd /
  rm -rf $temp_dir
  ln -s /usr/local/bin/aws /usr/bin/aws
}

function install_s3pcp() {
  set -euxo pipefail
  if s3pcp --help ; then
    return # putils already installed.
  fi

  temp_dir=$(mktemp -d)
  trap 'rm -rf $temp_dir' EXIT
  cd $temp_dir

  git clone https://github.com/allada/s3pcp.git
  cd $temp_dir/s3pcp
  make s3pcp
}

function install_putils() {
  set -euxo pipefail
  if psplit --help && pjoin --help ; then
    return # `putils` already installed.
  fi

  temp_dir=$(mktemp -d)
  trap 'rm -rf $temp_dir' EXIT
  cd $temp_dir

  git clone https://github.com/allada/putils.git
  cd $temp_dir/putils/psplit
  cargo build --release &
  cd $temp_dir/putils/pjoin
  cargo build --release &
  safe_wait
  mv $temp_dir/putils/psplit/target/release/psplit /usr/bin/psplit
  mv $temp_dir/putils/pjoin/target/release/pjoin /usr/bin/pjoin
}

function install_erigon() {
  set -euxo pipefail
  if erigon --help ; then
    return; # Erigon already installed.
  fi
  # Download, setup and install erigon.
  mkdir -p /erigon
  cd /erigon
  git clone https://github.com/ledgerwatch/erigon.git
  cd /erigon/erigon
  git checkout v2022.09.03
  CC=clang-12 CXX=clang++-12 CFLAGS="-O3" make erigon
  ln -s /erigon/erigon/build/bin/erigon /usr/bin/erigon

  # Stop the service if it exists.
  systemctl stop erigon-eth || true
}

# Lighthouse is the default consensus layer, you can replace this with another if you'd desire.
function setup_and_download_lighthouse_snapshot() {
  set -euxo pipefail
  # This will configure lighthouse to start and attach to erigon.
  export LIGHTHOUSE_WITH_ERIGON=1
  . <(curl https://raw.githubusercontent.com/allada/lighthouse-beacon-snapshot/master/build_lighthouse_beacon_node.sh)
}

function prepare_zfs_datasets() {
  set -euxo pipefail
  # Create datasets if needed.
  zfs create -o mountpoint=/erigon/data tank/erigon_data || true
  zfs create -o mountpoint=/erigon/data/eth tank/erigon_data/eth || true
}

function download_snapshots() {
  set -euxo pipefail
  if ! zfs list tank/erigon_data/eth/snapshots ; then
    # Setup zfs dataset and download the latest erigon snapshots into it if needed.
    zfs create -o mountpoint=/erigon/data/eth/snapshots tank/erigon_data/eth/snapshots
  fi
  mkdir -p /erigon/data/eth/snapshots/
  aws s3 sync \
      --quiet \
      --request-payer requester \
      s3://public-blockchain-snapshots/eth/erigon-snapshots-folder-latest/ \
      /erigon/data/eth/snapshots/
}

# This is not strictly required, but it will make it much faster for a node to join the pool.
function download_nodes() {
  set -euxo pipefail
  if ! zfs list tank/erigon_data/eth/nodes ; then
    zfs create -o mountpoint=/erigon/data/eth/nodes tank/erigon_data/eth/nodes
  fi
  # TODO(allada) Figure out a way to compress and decompress this. It has directories inside it
  # that refer to which protocol version it is using, so it's not easy to know if an upgrade
  # happens. The file is only about 1GB, so not a huge deal.
  aws s3 sync \
      --quiet \
      --request-payer requester \
      s3://public-blockchain-snapshots/eth/erigon-nodes-folder-latest/ \
      /erigon/data/eth/nodes/ \
  || true # This command is allowed to fail since it's only an optimization.
}

# This complicated bit of code accomplishes 2 goals.
# 1. In the event that the current file being downloaded gets updated while a user is
#    downloading the file, this configuration will be pinned to a specific version,
#    so it won't get interrupted in the middle of the download unless it takes over
#    ~24 hours.
# 2. Downloads many parts at a time and runs a parallelized decompressor. This is
#    about 3-4x faster than using normal `aws s3 cp` + `zstd -d`.
function download_database_file() {
  set -euxo pipefail
  if zfs list tank/erigon_data/eth/chaindata ; then
    return # Already have chaindata.
  fi
  zfs create -o mountpoint=/erigon/data/eth/chaindata tank/erigon_data/eth/chaindata

  s3pcp --requester-pays s3://public-blockchain-snapshots/eth/erigon-16k-db-latest.mdbx.zstd \
    | pv \
    | pzstd -p $(nproc) -q -d -f -o /erigon/data/eth/chaindata/mdbx.dat
}

function prepare_erigon() {
  set -euxo pipefail
  # Force creation of jwt.hex key. This is because we need this to exist for lighthouse too.
  if [ ! -f /erigon/data/eth/jwt.hex ]; then
    printf '0x' > /erigon/data/eth/jwt.hex
    openssl rand -hex 32 >> /erigon/data/eth/jwt.hex
    # This file must be readable by lighthouse user.
    chmod 744 /erigon/data/eth/jwt.hex
  fi

  # Create erigon user if needed.
  useradd erigon || true

  chown -R erigon:erigon /erigon/data/

  # Stop the service if it exists.
  systemctl stop erigon-eth || true

  echo '[Unit]
Description=Erigon ETH daemon
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=1
User=erigon
ExecStart=/erigon/start_erigon_service.sh

[Install]
WantedBy=multi-user.target
' > /etc/systemd/system/erigon-eth.service

  echo '#!/bin/bash' > /erigon/start_erigon_service.sh
  echo 'set -x' >> /erigon/start_erigon_service.sh
  if [[ "${SHOULD_AUTO_UPLOAD_SNAPSHOT:-}" == "1" ]]; then
    # Wait for erigon to get a block with a timestamp greater than a specific timestamp then kill erigon.
    cat <<'EOT' >> /erigon/start_erigon_service.sh
function stop_after_block_timestamp() {
  set -xe
  local stop_after_timestamp="$1"
  local process_id="$2"
  while sleep 10; do
    local hex=$(curl -s -H "Content-Type: application/json" -X POST --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest", false],"id":1}' 127.0.0.1:8545 \
                  | jq -r '.result.timestamp' \
                  | cut -c3-)
    local current_timestamp=$(echo "ibase=16; ${hex^^}" | bc)
    if [ "$current_timestamp" -gt "$stop_after_timestamp" ]; then
      kill $process_id || true
      return
    fi
  done
}

sh -c '
EOT
  fi

  echo "exec erigon --snapshots=true --datadir=/erigon/data/eth --txpool.disable" >> /erigon/start_erigon_service.sh

  if [[ "${SHOULD_AUTO_UPLOAD_SNAPSHOT:-}" == "1" ]]; then
    # Run in background because we want to make the non `SHOULD_AUTO_UPLOAD_SNAPSHOT` path pretty but keep
    # the ability to capture the proper process ids and such.
    echo "' &" >> /erigon/start_erigon_service.sh
    echo 'process_id=$!' >> /erigon/start_erigon_service.sh

    # Wait for erigon to process a block with a timstamp greater than now then kill erigon.
    echo 'stop_after_block_timestamp "$(date +"%s")" "$process_id"' >> /erigon/start_erigon_service.sh

    echo 'wait $process_id || true' >> /erigon/start_erigon_service.sh
    # In case the parent bash script gets interrupted, we want to double ensure our erigon process gets
    # terminated too.
    echo 'kill $process_id || true' >> /erigon/start_erigon_service.sh
    # Trick used to wait for process to fully terminate.
    echo 'tail --pid=$process_id -f /dev/null' >> /erigon/start_erigon_service.sh
    # Run our `create-eth-snapshot-and-shutdown.sh` script as root (without needing sudoer).
    echo 'super create-eth-snapshot-and-shutdown' >> /erigon/start_erigon_service.sh
  fi

  chmod +x /erigon/start_erigon_service.sh

  systemctl daemon-reload
  systemctl enable erigon-eth
}

function run_erigon() {
  set -euxo pipefail
  systemctl start erigon-eth
}

function add_create_snapshot_script() {
  set -euxo pipefail
  # Create script that can be used to upload a snapshot quickly.
  cat <<'EOT' > /erigon/create-eth-snapshot-and-shutdown.sh
#!/bin/bash
set -ex

export PATH="$PATH:/usr/sbin"

# Once the snapshot is created shutdown our node.
# A cronjob should start up the node again.
trap 'shutdown now' EXIT

function upload_mdbx_file() {
  upload_id=$(aws s3api create-multipart-upload \
      --bucket public-blockchain-snapshots \
      --key eth/erigon-16k-db-latest.mdbx.zstd \
      --request-payer requester \
    | jq -r ".UploadId")

  bytes_per_chunk=$(( 1024 * 1024 * 512 )) # 500mib.

  avail_mem_kb=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
  # Reduce the theoretical size by about 60% because there are 2 copies in memory at all times.
  parallel_downloads=$(( avail_mem_kb * 1000 / bytes_per_chunk * 10 / 25 ))
  num_cores=$(nproc)
  # We want more than the number of cores but not by a lot.
  max_parallel_downloads=$(echo "x = ($num_cores + 5) * 1.5; scale=0; x / 1" | bc -l)
  if [ $parallel_downloads -gt $max_parallel_downloads ]; then
    parallel_downloads=$max_parallel_downloads
  fi

  mkdir -p /erigon_upload_tmp
  mount -t tmpfs -o rw,size=$(( parallel_downloads * bytes_per_chunk + 1024 * 1024 )) tmpfs /erigon_upload_tmp
  trap "umount /erigon_upload_tmp" EXIT
  mkdir -p /erigon_upload_tmp/working_stdout
  mkdir -p /erigon_upload_tmp/upload_part_results

  # Sadly s3api/boto3 does not support streaming file descriptors. This means we need to write
  # our entire chunk to a file then upload that file. This probably isn't a big deal since the
  # data is in memory anyway
  pzstd \
      -p $parallel_downloads \
      -3 \
      -v \
      --stdout \
      /erigon/data/eth/chaindata/mdbx.dat \
    | psplit \
      -b $bytes_per_chunk \
      "bash -euo pipefail -c ' \
         SEQ=\$(( \$SEQ + 1 )) && \
         md5_value=\$(tee /erigon_upload_tmp/working_stdout/\$(printf %05d \$SEQ) | md5sum | cut -c -32) && \
         trap \"rm -rf /erigon_upload_tmp/working_stdout/\$(printf %05d \$SEQ)\" EXIT && \
         etag_result=\$(aws s3api upload-part \
            --body /erigon_upload_tmp/working_stdout/\$(printf %05d \$SEQ) \
            --request-payer requester \
            --bucket public-blockchain-snapshots \
            --key eth/erigon-16k-db-latest.mdbx.zstd \
            --upload-id $upload_id \
            --part-number \$SEQ \
        | jq -r .ETag | tr -d \\\" | tee > /erigon_upload_tmp/upload_part_results/\$(printf %05d \$SEQ)') && \
        if [ \$md5_value -ne \$etag_result ]; then echo \"md5 did not match \$md5_value -ne \$etag_result\" >&2 ; exit 1; fi"

  # Sadly `aws s3api complete-multipart-upload` requires the `multipart-upload` field be sent as an
  # argument which is too large to send over an argument, so we use a short python script to finish.
  python3 -c "
import boto3, os
part_nums=os.listdir('/erigon_upload_tmp/upload_part_results/')
part_nums.sort()
boto3.client('s3').complete_multipart_upload(
    Bucket='public-blockchain-snapshots',
    Key='eth/erigon-16k-db-latest.mdbx.zstd',
    UploadId='$upload_id',
    RequestPayer='requester',
    MultipartUpload={
        'Parts': [{'PartNumber': int(name), 'ETag': open('/erigon_upload_tmp/upload_part_results/' + name).readline().strip()} for name in part_nums]
    }
)"
}

zfs set readonly=on tank/erigon_data/eth/snapshots
aws s3 sync /erigon/data/eth/snapshots s3://public-blockchain-snapshots/eth/erigon-snapshots-folder-latest/ &

zfs set readonly=on tank/erigon_data/eth/nodes
aws s3 sync /erigon/data/eth/nodes s3://public-blockchain-snapshots/eth/erigon-nodes-folder-latest/ &

zfs set readonly=on tank/erigon_data/eth/chaindata
upload_mdbx_file &

# Stop our lighthouse-beacon so we can safely upload it.
systemctl stop lighthouse-beacon

# Note: ZFS readonly will happen in this script.
/lighthouse/create-lighthouse-snapshot.sh &

# If one of the background tasks has a bad exit code it's ok.
wait # Wait for all background tasks to finish.
EOT
  chmod 0744 /erigon/create-eth-snapshot-and-shutdown.sh
  chown root:root /erigon/create-eth-snapshot-and-shutdown.sh

  echo "create-eth-snapshot-and-shutdown     /erigon/create-eth-snapshot-and-shutdown.sh uid=root erigon" >> /etc/super.tab
}

mutex_function install_prereq
mutex_function setup_drives

# Because we run our commands in a subshell we want to give cargo access to all future commands.
. "$HOME/.cargo/env"

# These installations can happen in parallel.
mutex_function install_zstd &

mutex_function install_aws_cli &
mutex_function install_s3pcp &
mutex_function install_putils &
mutex_function install_erigon &
safe_wait # Wait for our parallel jobs finish.

mutex_function prepare_zfs_datasets

mutex_function setup_and_download_lighthouse_snapshot &
mutex_function download_snapshots & # Download just the snapshots folder.
mutex_function download_nodes & # Downloads the last known list of nodes.
mutex_function download_database_file & # Download the database file. This is the bulk of the downloads.
safe_wait # Wait for download_snapshot to finish.

mutex_function prepare_erigon
mutex_function run_erigon
mutex_function add_create_snapshot_script
