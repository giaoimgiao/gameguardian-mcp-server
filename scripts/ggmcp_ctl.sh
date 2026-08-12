#!/system/bin/sh
# ggmcp_ctl.sh - GameGuardian MCP 服务器开关
# 用法: ggmcp_ctl.sh start|stop|restart|status
# 开机自启由 /data/adb/service.d/ggmcp.sh 调用本脚本 start

DIR=/data/local/tmp/ggmcp
BIN=$DIR/ggmcp
LOG=$DIR/ggmcp.log
PORT=8788

case "$1" in
start)
	pkill -x ggmcp 2>/dev/null
	sleep 1
	# 二进制不存在时从备份目录恢复(避免部署时被旧文件覆盖的坑)
	if [ ! -x "$BIN" ]; then
		[ -f /sdcard/ggsetup/ggmcp ] && cp /sdcard/ggsetup/ggmcp "$BIN"
	fi
	chmod 755 "$BIN" 2>/dev/null
	cd "$DIR" || exit 1
	setsid nohup ./ggmcp :$PORT > "$LOG" 2>&1 < /dev/null &
	sleep 1
	if ps -A | grep -q ggmcp; then
		echo "GGMCP STARTED (port $PORT, log $LOG)"
	else
		echo "GGMCP FAILED (see $LOG)"
		exit 1
	fi
	;;
stop)
	pkill -x ggmcp 2>/dev/null
	echo "GGMCP STOPPED"
	;;
restart)
	$0 stop
	sleep 1
	$0 start
	;;
status)
	if ps -A | grep -q ggmcp; then
		echo "GGMCP RUNNING ($(ps -A | grep ggmcp | awk '{print $2}'))"
	else
		echo "GGMCP NOT RUNNING"
	fi
	;;
*)
	echo "usage: $0 start|stop|restart|status"
	;;
esac
