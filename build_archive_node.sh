#!/bin/bash
# Copyright 2021-2023 Nathan (Blaise) Bruer
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


# Curious on why this script is so complicated when it is just downloading stuff and
# configuring erigon?
#
# The short answer is because it costs a lot of money to maintain archive snapshots and
# I needed to use a lot of tricks to save money. Some of the tricks I used are:
# * When downloading the snapshots, use as much system resources as possible to get the
#   data on disk as fast as possible. This is why there is so much parallelism happening.
# * Similar to above, when uploading is happening, use mega-parallelism.
# * Compress the data as much as possible, as the data is quite large.
# * When uploading the snapshots directory (~25% of the archive size), only upload the
#   parts that changed. This saves ~25% of upload time.
# * There is/was not a lot of references on how to run an archive node. This script gives
#   a reference guide on how to do it, which is why there's so much setup.
# * At one point I frequently had users complain that the download would abruptly stop
#   when downloading outside of us-west-2. This is because I simply replace existing
#   files in s3 and have the s3 bucket configured to delete old versions of the file
#   after a few days. This caused users download to be interrupted if a new version
#   was uploaded while they are downloading. To solve this, I wrote a custom downloader
#   that first queries the most recent version, then downloads that version specifically.


# If set to "1", will create a crontab entry to upload a snapshot daily.
# This requires write permission to `s3://public-blockchain-snapshots`.
# You may also set this through an environmental variable at startup.
# SHOULD_AUTO_UPLOAD_SNAPSHOT="0"

# Below is just a comment. It is done this way to make copy and paste much easier.
# These are the commands used to create an image of a snapshot node.
# When it's done the instance will reboot.
# Make sure you launch the instance with the EC2 tag attached to the instance of:
# `no-launch` set to something and the `Allow tags in metadata` flag checked.
cat <<EOF > /dev/null
sudo sh -c 'curl https://raw.githubusercontent.com/allada/eth-archive-snapshot/master/build_archive_node.sh > /home/ubuntu/build_archive_node.sh'
sudo sh -c "echo \"@reboot root sh -c 'curl --fail http://169.254.169.254/latest/meta-data/tags/instance/no-launch || SHOULD_AUTO_UPLOAD_SNAPSHOT=1 /home/ubuntu/build_archive_node.sh || shutdown +5 now'\" >> /etc/crontab"
sudo chmod +x /home/ubuntu/build_archive_node.sh
sudo CREATE_SNAPSHOT_MODE=1 /home/ubuntu/build_archive_node.sh
EOF

function safe_wait() {
  BACKGROUND_PIDS=( $(jobs -p) )
  for PID in "${BACKGROUND_PIDS[@]}"; do
    wait -f $PID
  done
}

# This is pretty much the same as: `aws s3 sync s3://foo/bar /foo/bar`, but with better
# parallelization.
function parallel_sync_download() {
  set -euo pipefail
  full_s3_path=$1
  shift
  local_path=$1
  shift

  s3_bucket=$(echo "$full_s3_path" | cut -d'/' -f3)
  s3_path="${full_s3_path#s3://$s3_bucket/}"

  num_cores=$(nproc)
  # This is an inverse log10(). The lower the number of cores you have the more processes you'll
  # spawn. The logic here is that on less powerful machines you'll almost certainly want more
  # than 1 download going on at a time. The same in reverse, on 128 core machines, you will be
  # limited by network instead of cpu ability. 128 cores = 73 jobs, 64 cores = 42 jobs,
  # 32 cores = 25 jobs, 16 cores = 16 jobs, 4 cores = 8 jobs, exc...
  parallel_count=$(echo "x = $num_cores / (l($num_cores) / l(16)); scale=0; x / 1" | bc -l)

  set +x # Reduces the noise of commands being generated.

  # Download all the individual files from aws, decompress them, then place them into the snapshots
  # folder. This is similar to running:
  #   aws s3 sync --request-payer=requester s3://public-blockchain-snapshots/eth/erigon/archive/latest/v1/snapshots/ /erigon/data/eth/snapshots/
  # The major difference is that it will, while downloading, decompress each file.
  commands=()
  for aws_path in $(aws s3 ls --request-payer=requester --recursive "$full_s3_path" | tr -s ' ' ' ' | cut -d' ' -f4); do
    relative_path=$(dirname "${aws_path#$s3_path}")
    file=$(basename $aws_path)

    read_remote_file="aws s3 cp --request-payer=requester s3://$s3_bucket/$aws_path -"
    mkdir -p "$local_path/$relative_path"
    decompress="pzstd -d -q --stdout"
    save_to_file="cat > $local_path/$relative_path/${file%.zstd}"
    commands+=("sh -c '$read_remote_file | $decompress | $save_to_file'")
  done
  ( IFS=$'\n'; echo "${commands[*]}" ) | \
    pjoin --parallel-count $parallel_count
}

function install_prereq() {
  set -euxo pipefail
  # Basic installs.
  apt update
  DEBIAN_FRONTEND=noninteractive apt install -y zfsutils-linux unzip pv clang-12 make jq python3-boto3 super
  # Use clang as our compiler by default if needed.
  ln -s $(which clang-12) /usr/bin/cc || true
  snap install --classic go

  if ! cargo --version 2>&1 >/dev/null ; then
    # Install cargo.
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash /dev/stdin -y --default-toolchain=1.64.0
    source "$HOME/.cargo/env"
  fi
}

function setup_drives() {
  set -euxo pipefail
  if zfs list tank ; then
    return # Our drives are probably already setup.
  fi
  # Creates a new pool with the default device.
  DEVICES=( $(lsblk --fs --json | jq -r '.blockdevices[] | select(.children == null and .fstype == null and (.name | test("loop") | not)) | .name') )
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
  git checkout v2.36.0
  CC=clang-12 CXX=clang++-12 CFLAGS="-O3" make erigon
  ln -s /erigon/erigon/build/bin/erigon /usr/bin/erigon

  # Stop the service if it exists.
  systemctl stop erigon-eth || true
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

  parallel_sync_download s3://public-blockchain-snapshots/eth/erigon/archive/latest/v1/snapshots/ /erigon/data/eth/snapshots/

  # We then need to touch each .idx file. This is because erigon needs each .idx file to have an
  # mtime greater than the .seq file.
  find /erigon/data/eth/snapshots/ -type f -name "*.idx" -exec touch {} \;
}

# This is not strictly required, but it will make it much faster for a node to join the pool.
function download_nodes() {
  set -euxo pipefail
  if ! zfs list tank/erigon_data/eth/nodes ; then
    zfs create -o mountpoint=/erigon/data/eth/nodes tank/erigon_data/eth/nodes
  fi

  # This command is allowed to fail.
  parallel_sync_download s3://public-blockchain-snapshots/eth/erigon/archive/latest/v1/nodes/ /erigon/data/eth/nodes/nodes/ || true
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
  if ! zfs list tank/erigon_data/eth/chaindata ; then
    zfs create -o mountpoint=/erigon/data/eth/chaindata tank/erigon_data/eth/chaindata
  fi

  # Remove the file if it exists.
  rm -rf /erigon/data/eth/chaindata/mdbx.dat || true

  s3pcp --requester-pays s3://public-blockchain-snapshots/eth/erigon/archive/latest/v1/chaindata/mdbx.dat.zstd \
    | pv \
    | pzstd -p $(nproc) -q -d -f -o /erigon/data/eth/chaindata/mdbx.dat
}

function prepare_erigon() {
  set -euxo pipefail

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
      --key eth/erigon/archive/latest/v1/chaindata/mdbx.dat.zstd \
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
            --key eth/erigon/archive/latest/v1/chaindata/mdbx.dat.zstd \
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
    Key='eth/erigon/archive/latest/v1/chaindata/mdbx.dat.zstd',
    UploadId='$upload_id',
    RequestPayer='requester',
    MultipartUpload={
        'Parts': [{'PartNumber': int(name), 'ETag': open('/erigon_upload_tmp/upload_part_results/' + name).readline().strip()} for name in part_nums]
    }
)"
}

# Note: This will also delete remote files that are not local.
# This is pretty much the same as `aws s3 sync /local/folder/ s3://foo/bar/`, but better
# parallization.
function parallel_sync_upload() {
  set +x
  local_path=$1
  shift
  full_s3_path=$1
  shift

  s3_bucket=$(echo "$full_s3_path" | cut -d'/' -f3)
  s3_path="${full_s3_path#s3://$s3_bucket/}"
  s3_path="${s3_path%/}"

  local_files=$(find $local_path -type f | cut -c$((${#local_path}+1))- | sed -e 's/$/.zstd/' | sort)
  remote_files=$(aws s3 ls --recursive "$full_s3_path" | tr -s ' ' ' ' | cut -d' ' -f4 | cut -c$((${#s3_path}+2))- | sort)
  files_to_remove=$(comm -13 <(echo "$local_files") <(echo "$remote_files"))
  files_to_upload=$(comm -23 <(echo "$local_files") <(echo "$remote_files"))
  set -x
  for s3_delete_file in $files_to_remove ; do
    aws s3 rm "s3://$s3_bucket/$s3_path/$s3_delete_file"
  done

  num_cores=$(nproc)
  # This is an inverse log10(). The lower the number of cores you have the more processes you'll
  # spawn. The logic here is that on less powerful machines you'll almost certainly want more
  # than 1 download going on at a time. The same in reverse, on 128 core machines, you will be
  # limited by network instead of cpu ability. 128 cores = 85 jobs, 64 cores = 50 jobs,
  # 32 cores = 31 jobs, 16 cores = 20 jobs, 4 cores = 10 jobs, exc...
  parallel_count=$(echo "x = $num_cores / (l(($num_cores + 2) / 2) / l(16)); scale=0; x / 1" | bc -l)

  # Download all the individual files from aws, decompress them, then place them into the snapshots
  # folder. This is similar to running:
  #   aws s3 sync --request-payer=requester $full_s3_path $local_path
  # The major difference is that it will, while downloading, decompress each file.
  commands=()
  for relative_path_with_zstd in $files_to_upload ; do
    relative_path="${relative_path_with_zstd%.zstd}"
    compress_file="pzstd -6 -q --stdout $local_path/$relative_path"
    upload_file="aws s3 cp - ${full_s3_path%}${relative_path}.zstd"
    commands+=("sh -c '$compress_file | $upload_file'")
  done
  if [ "${#commands[@]}" -gt 0 ] ; then
    ( IFS=$'\n'; echo "${commands[*]}" ) | pjoin --parallel-count $parallel_count
  fi
}

zfs set readonly=on tank/erigon_data/eth/snapshots
parallel_sync_upload /erigon/data/eth/snapshots/ s3://public-blockchain-snapshots/eth/erigon/archive/latest/v1/snapshots/ &

zfs set readonly=on tank/erigon_data/eth/nodes
parallel_sync_upload /erigon/data/eth/nodes/ s3://public-blockchain-snapshots/eth/erigon/archive/latest/v1/nodes/ &

zfs set readonly=on tank/erigon_data/eth/chaindata
upload_mdbx_file &

# If one of the background tasks has a bad exit code it's ok.
wait # Wait for all background tasks to finish.
EOT
  chmod 0744 /erigon/create-eth-snapshot-and-shutdown.sh
  chown root:root /erigon/create-eth-snapshot-and-shutdown.sh

  echo "create-eth-snapshot-and-shutdown     /erigon/create-eth-snapshot-and-shutdown.sh uid=root erigon" >> /etc/super.tab
}

install_prereq
install_aws_cli

# Check to see if the user has AWS credentials configured.
if ! aws s3 ls --request-payer=requester s3://public-blockchain-snapshots ; then
  echo "It appears you do not have AWS credentials configured on this computer or user."
  echo "Normally this can be fixed by running 'aws configure' (maybe with sudo)."
  echo "Please see the following link for more details:"
  echo "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-quickstart.html"
  exit 1
fi

# Because we run our commands in a subshell we want to give cargo access to all future commands.
source "$HOME/.cargo/env"

setup_drives

# Overlay the tmp folder because our builds use it. Later we will revert it back.
zfs create -o mountpoint=/tmp tank/tmp

# These installations can happen in parallel.
install_zstd &
install_s3pcp &
install_putils &
install_erigon &
safe_wait # Wait for our parallel jobs finish.

# Revert back our tmp directory.
zfs destroy tank/tmp

# This should only be set if we are only configuring the instance for an EBS snapshot.
# Only set this global if you want to create your own snapshots and create an image of
# this instance as a template for faster startup.
if [[ "${CREATE_SNAPSHOT_MODE:-}" == "1" ]]; then
  apt update
  # This fixes an error when upgrading default ubuntu 22.04 instance.
  DEBIAN_FRONTEND=noninteractive apt install -y grub-efi-arm64
  DEBIAN_FRONTEND=noninteractive apt upgrade -y
  shutdown -r +1
  exit
fi

prepare_zfs_datasets

download_snapshots & # Download just the snapshots folder.
download_nodes & # Downloads the last known list of nodes.
download_database_file & # Download the database file. This is the bulk of the downloads.
safe_wait # Wait for download_snapshot to finish.

prepare_erigon
run_erigon
add_create_snapshot_script
