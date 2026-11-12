SKIPUNZIP=0

export PATH="/data/adb/ap/bin:/data/adb/ksu/bin:/data/adb/magisk:$PATH"

# Fallback (English)
LANG_NAME="English"
TXT_TERMUX_SHORTCUT="Termux shortcut 'overridify' created"

LANG_DIR="$MODPATH/common/languages"
SYS_LOCALE="$LANG $LC_ALL $LC_MESSAGES $(getprop persist.sys.locale) $(getprop persist.sys.locales) $(settings get system system_locales 2>/dev/null) $(getprop ro.product.locale)"
case "$SYS_LOCALE" in
    *[rR][uU]*|*[bB][yY]*|*[kK][zZ]*|*[uU][aA]*|*[uU][kK]*) [ -f "$LANG_DIR/ru.sh" ] && . "$LANG_DIR/ru.sh" ;;
esac

detect_soc() {
    local hw=$(getprop ro.hardware)
    local plat=$(getprop ro.board.platform)
    local soc_mfg=$(getprop ro.soc.manufacturer)
    if echo "$hw $plat $soc_mfg" | grep -qiE "qcom|qti|msm|sm[0-9]|kona|lahaina|taro|kalama|pineapple"; then
        echo "Qualcomm"
    elif echo "$hw $plat $soc_mfg" | grep -qiE "mt[0-9]|mediatek|dimensity"; then
        echo "MediaTek"
    else
        echo "Generic"
    fi
}

SOC_TYPE=$(detect_soc)
ui_print "- Detected SoC: $SOC_TYPE | SDK: $API"
ui_print "- Language: $LANG_NAME"

# Сохранение пользовательских настроек при обновлении модуля
if [ -f "/data/adb/modules/overridify/system.prop" ] && [ "$MODPATH" != "/data/adb/modules/overridify" ]; then
    cp -f "/data/adb/modules/overridify/system.prop" "$MODPATH/system.prop" 2>/dev/null
fi
if [ -f "/data/adb/modules/overridify/language.cfg" ] && [ "$MODPATH" != "/data/adb/modules/overridify" ]; then
    cp -f "/data/adb/modules/overridify/language.cfg" "$MODPATH/language.cfg" 2>/dev/null
fi
if [ -d "/data/adb/modules/overridify/custom_presets" ] && [ "$MODPATH" != "/data/adb/modules/overridify" ]; then
    mkdir -p "$MODPATH/custom_presets" 2>/dev/null
    cp -rf "/data/adb/modules/overridify/custom_presets/"* "$MODPATH/custom_presets/" 2>/dev/null
fi
if [ ! -s "$MODPATH/system.prop" ]; then
    echo "# Overridify system.prop" > "$MODPATH/system.prop"
fi

touch "$MODPATH/skip_mount"
touch "$MODPATH/skip_mountify"

# Интеграция ярлыка в Termux
TERMUX_BIN="/data/data/com.termux/files/usr/bin"
if [ -d "$TERMUX_BIN" ]; then
    cat << 'EOF' > "$TERMUX_BIN/overridify"
#!/data/data/com.termux/files/usr/bin/sh
unset LD_PRELOAD
unset LD_LIBRARY_PATH

CMD="/data/adb/modules/overridify/bin/overridify"
for b in \
    /data/adb/modules_update/overridify/bin/overridify \
    /data/adb/modules/overridify/bin/overridify \
    /data/adb/ksu/bin/overridify \
    /data/adb/ap/bin/overridify \
    /data/adb/bin/overridify \
    /system/bin/overridify; do
    if [ -x "$b" ] || su -c "[ -x '$b' ]" 2>/dev/null; then
        CMD="$b"
        break
    fi
done
if [ "$(id -u)" = "0" ]; then
    exec "$CMD" "$@"
elif [ $# -eq 0 ]; then
    exec su -c "$CMD"
else
    ARGS=""
    for a in "$@"; do
        ARGS="$ARGS \"$a\""
    done
    exec su -c "$CMD$ARGS"
fi
EOF
    chmod 0755 "$TERMUX_BIN/overridify"
    chown $(stat -c '%U:%G' "$TERMUX_BIN") "$TERMUX_BIN/overridify" 2>/dev/null
    ui_print "[+] ${TXT_TERMUX_SHORTCUT:-Termux shortcut 'overridify' created}"
fi

# Установка прав на исполняемые файлы
for b in overridify overridify-scan mawk mali-patcher; do
    if [ -f "$MODPATH/bin/$b" ]; then
        chmod 0755 "$MODPATH/bin/$b"
        chown 0:0 "$MODPATH/bin/$b" 2>/dev/null
        if command -v set_perm >/dev/null 2>&1; then
            set_perm "$MODPATH/bin/$b" 0 0 0755
        fi
    fi
done
[ -f "$MODPATH/uninstall.sh" ] && chmod 0755 "$MODPATH/uninstall.sh"

# Резервные симлинки в system/bin модуля
mkdir -p "$MODPATH/system/bin" 2>/dev/null
for b in overridify overridify-scan mawk mali-patcher; do
    [ -f "$MODPATH/bin/$b" ] && ln -sf "$MODPATH/bin/$b" "$MODPATH/system/bin/$b" 2>/dev/null
done

CANONICAL_BIN="/data/adb/modules/overridify/bin"
for bindir in /data/adb/bin /data/adb/ksu/bin /data/adb/ap/bin /data/adb/magisk; do
    if [ -d "$bindir" ] || [ "$bindir" = "/data/adb/bin" ]; then
        mkdir -p "$bindir" 2>/dev/null
        ln -sf "$CANONICAL_BIN/overridify" "$bindir/overridify" 2>/dev/null
        rm -f "$bindir/mawk" "$bindir/overridify-scan" "$bindir/mali-patcher" 2>/dev/null
    fi
done
