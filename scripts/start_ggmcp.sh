#!/system/bin/sh
# start_ggmcp.sh
pkill -x ggmcp 2>/dev/null
sleep 1
cp /sdcard/ggsetup/ggmcp /data/local/tmp/ggmcp/ggmcp
chmod 755 /data/local/tmp/ggmcp/ggmcp
cd /data/local/tmp/ggmcp
setsid nohup ./ggmcp :8788 > ggmcp.log 2>&1 < /dev/null &
sleep 1
ps -A | grep ggmcp
cat ggmcp.log