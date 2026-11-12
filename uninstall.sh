#!/system/bin/sh

for bindir in /data/adb/bin /data/adb/ksu/bin /data/adb/ap/bin /data/adb/magisk; do
    rm -f "$bindir/overridify" "$bindir/overridify-scan" "$bindir/mawk" "$bindir/mali-patcher" 2>/dev/null
done

rm -f /data/data/com.termux/files/usr/bin/overridify 2>/dev/null
rm -f /data/data/com.termux/files/usr/bin/mawk 2>/dev/null
rm -rf /data/local/tmp/overridify* 2>/dev/null
