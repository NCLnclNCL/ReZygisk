#!/system/bin/sh

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ]; then
  exit 0
fi

cd "$MODDIR"

if [ "$(which magisk)" ]; then
  for file in ../*; do
    if [ -d "$file" ] && [ -d "$file/zygisk" ] && ! [ -f "$file/disable" ]; then
      if [ -f "$file/post-fs-data.sh" ]; then
        cd "$file"
        log -p i -t "zygisk-sh" "Manually trigger post-fs-data.sh for $file"
        sh "$(realpath ./post-fs-data.sh)"
        cd "$MODDIR"
      fi
    fi
  done
fi

create_sys_perm() {
  mkdir -p $1
  chmod 555 $1
  chcon u:object_r:system_file:s0 $1
}

export TMP_PATH=/data/adb/nrezygisk

if [ -d $TMP_PATH ]; then
  rm $TMP_PATH/cp32.sock 2>/dev/null
  rm $TMP_PATH/cp64.sock 2>/dev/null
  rm $TMP_PATH/init_monitor 2>/dev/null
  rm $TMP_PATH/mns32 2>/dev/null
  rm $TMP_PATH/mns64 2>/dev/null
  rm -rf "$TMP_PATH/tmp"
fi

create_sys_perm $TMP_PATH
create_sys_perm $TMP_PATH/tmp

mkdir $TMP_PATH/tmp/copy32_d
mkdir $TMP_PATH/tmp/copy64_d
touch $TMP_PATH/tmp/copy32_f
touch $TMP_PATH/tmp/copy64_f

if [ -f $MODDIR/lib64/libzygisk.so ];then
  create_sys_perm $TMP_PATH/lib64
  cp $MODDIR/lib64/libzygisk.so $TMP_PATH/lib64/libzygisk.so
  chcon u:object_r:system_file:s0 $TMP_PATH/lib64/libzygisk.so
fi

if [ -f $MODDIR/lib/libzygisk.so ];then
  create_sys_perm $TMP_PATH/lib
  cp $MODDIR/lib/libzygisk.so $TMP_PATH/lib/libzygisk.so
  chcon u:object_r:system_file:s0 $TMP_PATH/lib/libzygisk.so
fi


CPU_ABIS=$(getprop ro.product.cpu.abilist)

if [[ "$CPU_ABIS" == *"arm64-v8a"* || "$CPU_ABIS" == *"x86_64"* ]]; then
  ./bin/zygisk-ptrace64 monitor
  ./bin/zygisk-ptrace64 mount_ns
  ./bin/zygisk-ptrace64 mount_ns_private
else
  # INFO: Device is 32-bit only

  ./bin/zygisk-ptrace32 monitor
  ./bin/zygisk-ptrace32 mount_ns
  ./bin/zygisk-ptrace32 mount_ns_private
fi
