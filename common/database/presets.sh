#!/system/bin/sh
# Overridify — База пресетов переопределения (Override Presets & Profiles)
# Все пресеты построены на базе объективно верифицированных свойств прошивки (Zero-Hardcode)

PRESETS_ALL="vulkan smooth touch gaming"

if [ -z "$PROP_FILE" ]; then
    if [ -n "$MODDIR" ] && [ -f "$MODDIR/system.prop" ]; then
        PROP_FILE="$MODDIR/system.prop"
    elif [ -f "/data/adb/modules/overridify/system.prop" ]; then
        PROP_FILE="/data/adb/modules/overridify/system.prop"
    elif [ -f "/data/adb/modules_update/overridify/system.prop" ]; then
        PROP_FILE="/data/adb/modules_update/overridify/system.prop"
    fi
fi

CUSTOM_PRESETS_DIR="$MODDIR/custom_presets"
[ ! -d "$CUSTOM_PRESETS_DIR" ] && [ -d "/data/adb/modules_update/overridify/custom_presets" ] && CUSTOM_PRESETS_DIR="/data/adb/modules_update/overridify/custom_presets"
[ ! -d "$CUSTOM_PRESETS_DIR" ] && [ -d "/data/adb/modules/overridify/custom_presets" ] && CUSTOM_PRESETS_DIR="/data/adb/modules/overridify/custom_presets"
mkdir -p "$CUSTOM_PRESETS_DIR" 2>/dev/null

get_custom_presets() {
    [ ! -d "$CUSTOM_PRESETS_DIR" ] && return 0
    local list=""
    for f in "$CUSTOM_PRESETS_DIR"/cust_*.conf; do
        [ -f "$f" ] || continue
        local fname="${f##*/}"
        local cid="${fname%.conf}"
        list="${list:+$list }$cid"
    done
    echo "$list"
}

# Сборка единого быстрого индекса поддерживаемых прошивкой свойств в RAM (~3 мс один раз за сессию)
ensure_supported_props_cache() {
    local sup_f="$OVER_TMP_DIR/cache_supported_props.tmp"
    [ -s "$sup_f" ] && return 0

    local elf_f="" dex_f="" rc_f="$OVER_TMP_DIR/cache_rc_alive.tmp"
    for c in "$OVER_TMP_DIR/cache_elf_scan.tmp" "$OVER_CACHE_DIR/elf_scan.cache" "$MODDIR/cache/elf_scan.cache" "$MODDIR/elf_scan.cache"; do
        [ -s "$c" ] && { elf_f="$c"; break; }
    done
    for c in "$OVER_TMP_DIR/cache_dex_defaults.tmp" "$OVER_CACHE_DIR/dex_framework.cache" "$MODDIR/cache/dex_framework.cache" "$MODDIR/dex_framework.cache"; do
        [ -s "$c" ] && { dex_f="$c"; break; }
    done

    ${AWK_BIN:-awk} -v elf_f="$elf_f" -v dex_f="$dex_f" -v rc_f="$rc_f" '
    BEGIN {
        if (elf_f != "") {
            while ((getline l < elf_f) > 0) {
                if (l ~ /^#/) continue;
                p1 = index(l, "|");
                if (p1 > 1) {
                    p = substr(l, 1, p1 - 1);
                    rest = substr(l, p1 + 1);
                    if (rest !~ /^(NOT_A_PROPERTY|NOT_FOUND_IN_BINARY)\|/) sup[p] = 1;
                }
            }
            close(elf_f);
        }
        if (dex_f != "") {
            while ((getline l < dex_f) > 0) {
                if (l ~ /^#/) continue;
                eq = index(l, "=");
                if (eq == 0) eq = index(l, "|");
                if (eq > 1) sup[substr(l, 1, eq - 1)] = 1;
            }
            close(dex_f);
        }
        if (rc_f != "") {
            while ((getline l < rc_f) > 0) {
                if (l != "" && l !~ /[_.-]$/) sup[l] = 1;
            }
            close(rc_f);
        }
        for (k in sup) print k;
    }' > "$sup_f" 2>/dev/null
}

# Объективная проверка поддержки свойства бинарниками/байткодом/скриптами прошивки
is_prop_supported_on_device() {
    local prop="$1"
    [ -z "$prop" ] && return 1
    ensure_supported_props_cache
    local sup_f="$OVER_TMP_DIR/cache_supported_props.tmp"
    if [ -s "$sup_f" ]; then
        grep -q -x -F "$prop" "$sup_f" 2>/dev/null && return 0
    fi
    return 1
}

is_qualcomm() {
    [ "$SOC_TYPE" = "Qualcomm" ] && return 0
    return 1
}

get_overridify_mod_dir() {
    if [ -n "$MODDIR" ] && [ -d "$MODDIR" ]; then
        echo "$MODDIR"
    elif [ -d "/data/adb/modules/overridify" ]; then
        echo "/data/adb/modules/overridify"
    else
        echo "/data/data/com.termux/files/home/overridify"
    fi
}

find_mali_patcher_bin() {
    local b=""
    for b in "$MODDIR/bin/mali-patcher" \
             "$MODDIR/system/bin/mali-patcher" \
             "/data/adb/modules/overridify/bin/mali-patcher" \
             "/data/adb/modules/overridify/system/bin/mali-patcher" \
             "/data/data/com.termux/files/home/overridify/bin/mali-patcher" \
             "$CANONICAL_BIN/mali-patcher" \
             "$(command -v mali-patcher 2>/dev/null)"; do
        if [ -n "$b" ] && [ -x "$b" ]; then
            echo "$b"
            return 0
        fi
    done
    return 1
}

_MALI_DRV_STATUS=""

# 0: Buggy signature found (needs patch)
# 1: Already patched
# 2: Clean / Not Mali / Not affected
check_mali_driver_status() {
    if [ -n "$_MALI_DRV_STATUS" ]; then
        return "$_MALI_DRV_STATUS"
    fi
    local st_file="$OVER_TMP_DIR/mali_drv_status.tmp"
    if [ -f "$st_file" ]; then
        _MALI_DRV_STATUS=$(cat "$st_file" 2>/dev/null)
        [ -n "$_MALI_DRV_STATUS" ] && return "$_MALI_DRV_STATUS"
    fi
    local pbin="$(find_mali_patcher_bin)"
    _MALI_DRV_STATUS=2
    if [ -n "$pbin" ]; then
        local out="$($pbin status 2>/dev/null)"
        case "$out" in
            BUG_FOUND*)       _MALI_DRV_STATUS=0 ;;
            ALREADY_PATCHED*) _MALI_DRV_STATUS=1 ;;
            *)                _MALI_DRV_STATUS=2 ;;
        esac
    fi
    echo "$_MALI_DRV_STATUS" > "$st_file" 2>/dev/null
    return "$_MALI_DRV_STATUS"
}

is_mali_guard_active() {
    local mod="$(get_overridify_mod_dir)"
    [ -f "$mod/skip_mount" ] || [ -f "$mod/disable" ] && return 1
    [ -s "$mod/vendor/lib64/egl/libGLES_mali.so" ] || [ -s "$mod/system/vendor/lib64/egl/libGLES_mali.so" ] && return 0
    return 1
}

is_mali_guard_needed_or_active() {
    is_mali_guard_active && return 0
    check_mali_driver_status
    local st=$?
    [ "$st" -eq 0 ] || [ "$st" -eq 1 ] && return 0
    return 1
}

invalidate_presets_runtime_cache() {
    _MALI_DRV_STATUS=""
    rm -f "$OVER_TMP_DIR"/mali_drv_status.tmp "$OVER_TMP_DIR"/preset_eval_*.tmp \
          "$OVER_TMP_DIR"/radar_cache.txt "$OVER_TMP_DIR"/radar_meta.tmp 2>/dev/null
    if [ -n "$CACHE_LIVE_PROPS" ]; then
        getprop | tr -d '[]' | ${AWK_BIN:-awk} -F': ' '{print $1 "=" $2}' > "$CACHE_LIVE_PROPS" 2>/dev/null
    fi
}

apply_mali_guard_patch() {
    local mod="$(get_overridify_mod_dir)"
    local pbin="$(find_mali_patcher_bin)"
    [ -z "$pbin" ] && return 1

    local src_drv="$($pbin find 2>/dev/null)"
    [ -z "$src_drv" ] || [ ! -s "$src_drv" ] && return 1

    local rel_path="${src_drv#/vendor/lib64/egl/}"
    local dst_drv="$mod/vendor/lib64/egl/$rel_path"

    mkdir -p "$(dirname "$dst_drv")" 2>/dev/null

    if [ -s "$dst_drv" ]; then
        local dst_st="$($pbin status "$dst_drv" 2>/dev/null)"
        case "$dst_st" in
            ALREADY_PATCHED*) ;;
            *)
                $pbin patch "$src_drv" "$dst_drv" >/dev/null 2>&1 || return 1
                ;;
        esac
    else
        $pbin patch "$src_drv" "$dst_drv" >/dev/null 2>&1 || return 1
    fi

    if [ ! -s "$dst_drv" ]; then
        rm -f "$dst_drv" 2>/dev/null
        return 1
    fi

    if [ "$rel_path" != "libGLES_mali.so" ]; then
        ln -sf "$rel_path" "$mod/vendor/lib64/egl/libGLES_mali.so" 2>/dev/null
    fi

    mkdir -p "$mod/system" 2>/dev/null
    rm -rf "$mod/system/vendor" 2>/dev/null
    ln -sf "../vendor" "$mod/system/vendor" 2>/dev/null

    rm -f "$mod/skip_mount" "$mod/skip_mountify" "$mod/.nomount" 2>/dev/null

    if [ "$(id -u)" = "0" ]; then
        chmod 755 "$mod/vendor" "$mod/vendor/lib64" "$mod/vendor/lib64/egl" 2>/dev/null
        [ "$rel_path" != "libGLES_mali.so" ] && chmod 755 "$(dirname "$dst_drv")" 2>/dev/null
        chmod 644 "$dst_drv" 2>/dev/null
        chcon -R u:object_r:vendor_file:s0 "$mod/vendor" 2>/dev/null
        chcon u:object_r:same_process_hal_file:s0 "$dst_drv" 2>/dev/null
        [ -L "$mod/vendor/lib64/egl/libGLES_mali.so" ] && chcon -h u:object_r:same_process_hal_file:s0 "$mod/vendor/lib64/egl/libGLES_mali.so" 2>/dev/null
        chcon u:object_r:system_file:s0 "$mod/system" 2>/dev/null
        chcon -h u:object_r:system_file:s0 "$mod/system/vendor" 2>/dev/null
    fi

    cat << EOF > "$mod/post-fs-data.sh"
#!/system/bin/sh
MODDIR="\${0%/*}"
PATCHED="\$MODDIR/vendor/lib64/egl/$rel_path"
TARGET="$src_drv"

if [ ! -s "\$PATCHED" ]; then
    [ -f "\$MODDIR/system.prop" ] && sed -i -E '/(debug\.renderengine\.|vendor\.debug\.renderengine\.)/d' "\$MODDIR/system.prop" 2>/dev/null
    exit 0
fi

[ -f "\$MODDIR/skip_mount" ] && exit 0
[ -f "\$MODDIR/disable" ] && exit 0

if [ "\$(stat -c %i "\$TARGET" 2>/dev/null)" = "\$(stat -c %i "\$PATCHED" 2>/dev/null)" ]; then
    exit 0
fi

if [ -x /system/bin/nsenter ]; then
    /system/bin/nsenter -t 1 -m -- /system/bin/mount -o bind "\$PATCHED" "\$TARGET" 2>/dev/null
else
    mount -o bind "\$PATCHED" "\$TARGET" 2>/dev/null
fi
EOF
    chmod 755 "$mod/post-fs-data.sh" 2>/dev/null
    if [ "$(id -u)" = "0" ]; then
        chcon u:object_r:ksu_file:s0 "$mod/post-fs-data.sh" 2>/dev/null
    fi
    invalidate_presets_runtime_cache
    return 0
}

remove_mali_guard_patch() {
    local mod="$(get_overridify_mod_dir)"
    rm -rf "$mod/vendor" 2>/dev/null
    rm -rf "$mod/system/vendor" 2>/dev/null
    rm -f "$mod/post-fs-data.sh" 2>/dev/null
    touch "$mod/skip_mount" "$mod/skip_mountify" 2>/dev/null
    invalidate_presets_runtime_cache
    return 0
}

get_module_val() {
    [ -n "$PROP_FILE" ] && [ -f "$PROP_FILE" ] && {
        local l=$(grep -m 1 -E "^[[:space:]]*$1=" "$PROP_FILE" 2>/dev/null)
        [ -n "$l" ] && { echo "${l#*=}"; return; }
    }
    echo "---"
}

is_vulkan_active() {
    if [ -n "$PROP_FILE" ] && [ -f "$PROP_FILE" ]; then
        grep -qE "^[[:space:]]*((debug\.hwui\.renderer|vendor\.debug\.renderengine\.backend|debug\.renderengine\.backend)=skiavk|ro\.hwui\.use_vulkan=true)" "$PROP_FILE" 2>/dev/null && return 0
    fi
    if [ -s "$CACHE_LIVE_PROPS" ]; then
        grep -qE "^((debug\.hwui\.renderer|vendor\.debug\.renderengine\.backend|debug\.renderengine\.backend)=skiavk|ro\.hwui\.use_vulkan=true)$" "$CACHE_LIVE_PROPS" 2>/dev/null && return 0
    else
        [ "$(getprop debug.hwui.renderer)" = "skiavk" ] && return 0
        [ "$(getprop vendor.debug.renderengine.backend)" = "skiavk" ] && return 0
        [ "$(getprop ro.hwui.use_vulkan)" = "true" ] && return 0
    fi
    return 1
}

is_preset_supported() {
    local id="$1"
    [ -n "$(get_preset_props "$id")" ] && return 0
    return 1
}

get_supported_presets() {
    echo "$PRESETS_ALL"
}

get_preset_name() {
    local id="$1"
    case "$id" in
        vulkan) echo "${TXT_PRESET_VULKAN:-Vulkan UI Pipeline (2D & Compositor)}" ;;
        smooth) echo "${TXT_PRESET_SMOOTH:-UI Smoothness (Frame Pacing)}" ;;
        touch)  echo "${TXT_PRESET_TOUCH:-Touch Response (Low Input Latency)}" ;;
        gaming) echo "${TXT_PRESET_GAMING:-Gaming Mode (Sustained FPS Priority)}" ;;
        cust_*)
            local f="$CUSTOM_PRESETS_DIR/${id}.conf"
            if [ -f "$f" ]; then
                local name=$(grep -m 1 "^name=" "$f" 2>/dev/null | cut -d= -f2-)
                echo "${name:-$id}"
            else
                echo "$id"
            fi
            ;;
        *)      echo "$id" ;;
    esac
}

get_preset_desc() {
    local id="$1"
    case "$id" in
        vulkan) echo "${TXT_PRESET_VULKAN_DESC:-Comprehensive switch of Android Canvas and SurfaceFlinger to Vulkan API}" ;;
        smooth) echo "${TXT_PRESET_SMOOTH_DESC:-Eliminate micro-stutters: auto latch unsignaled, buffer age, SF scheduler}" ;;
        touch)  echo "${TXT_PRESET_TOUCH_DESC:-Minimize input latency: 0ms resample buffer, touch refresh rate hold}" ;;
        gaming) echo "${TXT_PRESET_GAMING_DESC:-Uncap game FPS limits, frame rate priority, Game Frame Rescue}" ;;
        cust_*)
            local f="$CUSTOM_PRESETS_DIR/${id}.conf"
            if [ -f "$f" ]; then
                local desc=$(grep -m 1 "^desc=" "$f" 2>/dev/null | cut -d= -f2-)
                echo "${desc:-}"
            else
                echo ""
            fi
            ;;
        *)  echo "" ;;
    esac
}

get_preset_props() {
    local id="$1"
    case "$id" in
        cust_*)
            local f="$CUSTOM_PRESETS_DIR/${id}.conf"
            if [ -f "$f" ]; then
                ${AWK_BIN:-awk} '!/^[[:space:]]*#/ && /=/ && !/^(name|desc)=/ { print }' "$f" 2>/dev/null
            fi
            return 0
            ;;
    esac

    ensure_supported_props_cache
    local sup_f="$OVER_TMP_DIR/cache_supported_props.tmp"

    local skip_sf=0
    if [ "$id" = "vulkan" ]; then
        check_mali_driver_status
        local mali_st=$?
        if [ "$mali_st" -eq 0 ] || [ "$mali_st" -eq 1 ]; then
            is_mali_guard_active || skip_sf=1
        fi
    fi

    local vk_act=0
    [ "$id" = "smooth" ] && is_vulkan_active && vk_act=1
    local qcom=0
    is_qualcomm && qcom=1

    local cache_f="$OVER_TMP_DIR/preset_eval_${id}_${skip_sf}_${vk_act}_${qcom}.tmp"
    if [ -f "$cache_f" ]; then
        cat "$cache_f"
        return 0
    fi

    ${AWK_BIN:-awk} -v id="$id" -v sup_f="$sup_f" -v skip_sf="$skip_sf" -v vk_act="$vk_act" -v qcom="$qcom" '
    BEGIN {
        if (sup_f != "") {
            while ((getline l < sup_f) > 0) if (l != "") sup[l] = 1;
            close(sup_f);
        }
        if (id == "vulkan") {
            if ("debug.hwui.renderer" in sup) print "debug.hwui.renderer=skiavk";
            if ("ro.hwui.use_vulkan" in sup) print "ro.hwui.use_vulkan=true";
            if (skip_sf == 0) {
                if ("debug.renderengine.backend" in sup) print "debug.renderengine.backend=skiavk";
                if ("vendor.debug.renderengine.backend" in sup) print "vendor.debug.renderengine.backend=skiavk";
                if ("debug.renderengine.vulkan" in sup) print "debug.renderengine.vulkan=1";
            }
            if ("ro.surface_flinger.enable_frame_rate_override" in sup) print "ro.surface_flinger.enable_frame_rate_override=false";
            if (qcom == 1) {
                if ("debug.sf.disable_client_composition_cache" in sup) print "debug.sf.disable_client_composition_cache=1";
                if ("ro.surface_flinger.enable_layer_caching" in sup) print "ro.surface_flinger.enable_layer_caching=false";
            }
            if ("ro.oplus.display.enable_skiavk" in sup) print "ro.oplus.display.enable_skiavk=true";
        } else if (id == "smooth") {
            if ("debug.sf.auto_latch_unsignaled" in sup) print "debug.sf.auto_latch_unsignaled=1";
            else if ("debug.sf.latch_unsignaled" in sup) print "debug.sf.latch_unsignaled=1";
            if ("debug.sf.enable_cached_set_render_scheduling" in sup) print "debug.sf.enable_cached_set_render_scheduling=1";
            if ("debug.sf.enable_planner_prediction" in sup) print "debug.sf.enable_planner_prediction=true";
            if ("debug.sf.predict_hwc_composition_strategy" in sup) print "debug.sf.predict_hwc_composition_strategy=1";
            if ("debug.sf.enable_layer_command_batching" in sup) print "debug.sf.enable_layer_command_batching=true";
            if ("debug.sf.enable_transaction_tracing" in sup) print "debug.sf.enable_transaction_tracing=false";
            if ("debug.sf.disable_backpressure" in sup) print "debug.sf.disable_backpressure=1";
            if ("vendor.debug.sf.display_dejitter" in sup) print "vendor.debug.sf.display_dejitter=1";
            if ("vendor.debug.sf.dynamic_duration.switch" in sup) print "vendor.debug.sf.dynamic_duration.switch=1";
            if ("ro.vendor.mi_sf.highfps_duration_enable" in sup) print "ro.vendor.mi_sf.highfps_duration_enable=true";
            if ("persist.sys.sf.releasebuf_rt" in sup) print "persist.sys.sf.releasebuf_rt=1";
            if ("ro.vendor.perf.scroll_opt" in sup) print "ro.vendor.perf.scroll_opt=true";
            if ("ro.vendor.perf.scroll_opt.heavy_app" in sup) print "ro.vendor.perf.scroll_opt.heavy_app=1";
            if ("persist.sys.performance.appCacheOptimization" in sup) print "persist.sys.performance.appCacheOptimization=true";
            if ("persist.sys.performance.appLaunchPreload.enable" in sup) print "persist.sys.performance.appLaunchPreload.enable=true";
            if ("persist.sys.turbosched.enable.coreApp.optimizer" in sup) print "persist.sys.turbosched.enable.coreApp.optimizer=true";
            if ("debug.hwui.use_hint_manager" in sup) print "debug.hwui.use_hint_manager=true";
            if ("debug.hwui.use_buffer_age" in sup) print "debug.hwui.use_buffer_age=true";
            if ("debug.hwui.use_partial_updates" in sup) print "debug.hwui.use_partial_updates=true";
            if ("debug.hwui.skip_empty_damage" in sup) print "debug.hwui.skip_empty_damage=true";
            if ("debug.hwui.skip_eglmanager_telemetry" in sup) print "debug.hwui.skip_eglmanager_telemetry=true";
            if (vk_act == 0 && ("debug.hwui.early_preload_gl_context" in sup)) print "debug.hwui.early_preload_gl_context=true";
        } else if (id == "touch") {
            if ("ro.input.resampling" in sup) print "ro.input.resampling=1";
            if ("sys.input.resample.latency" in sup) print "sys.input.resample.latency=0";
            if ("ro.surface_flinger.set_touch_timer_ms" in sup) print "ro.surface_flinger.set_touch_timer_ms=200";
            if ("persist.input.enable_motion_prediction" in sup) print "persist.input.enable_motion_prediction=true";
            if ("ro.vendor.touch.touchscheduler.enable" in sup) print "ro.vendor.touch.touchscheduler.enable=true";
            if ("ro.vendor.touch.touchflinger.enable" in sup) print "ro.vendor.touch.touchflinger.enable=true";
            if ("persist.sys.turbosched.speed_touch.enable" in sup) print "persist.sys.turbosched.speed_touch.enable=true";
            if ("sys.input.touchll.mode" in sup) print "sys.input.touchll.mode=game";
            if ("sys.input.touchll.log" in sup) print "sys.input.touchll.log=false";
            if ("vendor.perf.gestureflingboost.enable" in sup) print "vendor.perf.gestureflingboost.enable=true";
            if ("persist.sys.input.tracker.enable" in sup) print "persist.sys.input.tracker.enable=false";
            if ("persist.sys.input.statistics.enable" in sup) print "persist.sys.input.statistics.enable=false";
            if ("persist.debug.input.enable_input_device_usage_metrics" in sup) print "persist.debug.input.enable_input_device_usage_metrics=false";
        } else if (id == "gaming") {
            if ("ro.surface_flinger.game_default_frame_rate_override" in sup) print "ro.surface_flinger.game_default_frame_rate_override=0";
            if ("debug.sf.use_frame_rate_priority" in sup) print "debug.sf.use_frame_rate_priority=1";
            if ("debug.sf.disable_backpressure" in sup) print "debug.sf.disable_backpressure=1";
            if ("ro.vendor.mi_sf.144fps_duration_enable" in sup) print "ro.vendor.mi_sf.144fps_duration_enable=true";
            if ("persist.sys.enable_perf_hint" in sup) print "persist.sys.enable_perf_hint=true";
            if ("vendor.bluetooth.performance.game" in sup) print "vendor.bluetooth.performance.game=true";
            if ("vendor.bluetooth.performance.game_ultra" in sup) print "vendor.bluetooth.performance.game_ultra=true";
            if ("sys.input.touchll.mode" in sup) print "sys.input.touchll.mode=game";
            if ("vendor.perf.game_frame_rescue" in sup) print "vendor.perf.game_frame_rescue=1";
            if ("vendor.display.smomo_game_support" in sup) print "vendor.display.smomo_game_support=1";
            if ("ro.vendor.mtk.gpu.game_memc" in sup) print "ro.vendor.mtk.gpu.game_memc=true";
            if ("persist.bluetooth.gamemode" in sup) print "persist.bluetooth.gamemode=true";
        }
    }' | tee "$cache_f" 2>/dev/null
}

# Мгновенная пакетная отрисовка списка флагов пресета для Verbose-режима (~1 мс через AWK вместо десятков getprop/grep)
render_preset_flags_verbose() {
    local pprops="$1"
    local check_rom="${2:-0}"
    local indent="${3:-      }"
    if [ -z "$pprops" ]; then
        echo -e "${indent}${C_GRAY}${TXT_MANAGE_NO_FLAGS:-<no flags>}${C_RESET}"
        return 0
    fi
    ensure_supported_props_cache
    printf "%s\n" "$pprops" | ${AWK_BIN:-awk} \
        -v live_f="$CACHE_LIVE_PROPS" \
        -v sup_f="$OVER_TMP_DIR/cache_supported_props.tmp" \
        -v check_rom="$check_rom" \
        -v indent="$indent" \
        -v empty_lbl="${TXT_EMPTY:-<empty>}" \
        -v cur_lbl="${TXT_PRESET_CURRENT:-current: }" \
        -v not_rom_lbl="${TXT_PRESET_NOT_IN_ROM:-[not in ROM]}" '
    BEGIN {
        c_reset  = "\033[0m";
        c_bold   = "\033[1m";
        c_green  = "\033[1;32m";
        c_yellow = "\033[1;33m";
        c_red    = "\033[1;31m";
        c_gray   = "\033[0;90m";
        if (live_f != "") {
            while ((getline l < live_f) > 0) {
                eq = index(l, "=");
                if (eq > 1) live[substr(l, 1, eq - 1)] = substr(l, eq + 1);
            }
            close(live_f);
        }
        if (check_rom == 1 && sup_f != "") {
            while ((getline l < sup_f) > 0) if (l != "") sup[l] = 1;
            close(sup_f);
        }
    }
    /=/ {
        eq = index($0, "=");
        if (eq <= 1) next;
        pk = substr($0, 1, eq - 1);
        pv = substr($0, eq + 1);
        cur = (pk in live) ? live[pk] : "";
        disp_cur = (cur != "") ? cur : empty_lbl;
        cur_col = (cur == pv) ? c_green disp_cur c_reset : c_yellow disp_cur c_reset;
        rom_hint = (check_rom == 1 && !(pk in sup)) ? " " c_red not_rom_lbl c_reset : "";
        printf "%s%s├─%s %s%s%s=%s%s%s %s(%s%s%s)%s%s\n",
            indent, c_gray, c_reset, c_bold, pk, c_reset, c_green, pv, c_reset,
            c_gray, cur_lbl, cur_col, c_gray, c_reset, rom_hint;
    }'
}

get_preset_cleanup_keys() {
    local id="$1"
    case "$id" in
        vulkan|hwui|sf)
            echo "debug.hwui.renderer ro.hwui.use_vulkan debug.renderengine.backend vendor.debug.renderengine.backend debug.renderengine.vulkan debug.sf.enable_gl_backpressure ro.surface_flinger.enable_frame_rate_override debug.sf.disable_client_composition_cache ro.surface_flinger.enable_layer_caching ro.oplus.display.enable_skiavk debug.hwui.initialize_gl_always debug.hwui.early_preload_gl_context" ;;
        smooth)
            echo "debug.sf.auto_latch_unsignaled debug.sf.latch_unsignaled debug.sf.enable_cached_set_render_scheduling debug.sf.enable_planner_prediction debug.sf.predict_hwc_composition_strategy debug.sf.enable_layer_command_batching debug.sf.enable_transaction_tracing debug.sf.disable_backpressure vendor.debug.sf.display_dejitter vendor.debug.sf.dynamic_duration.switch ro.vendor.mi_sf.highfps_duration_enable persist.sys.sf.releasebuf_rt ro.vendor.perf.scroll_opt ro.vendor.perf.scroll_opt.heavy_app persist.sys.performance.appCacheOptimization persist.sys.performance.appLaunchPreload.enable persist.sys.turbosched.enable.coreApp.optimizer debug.hwui.use_hint_manager debug.hwui.use_buffer_age debug.hwui.use_partial_updates debug.hwui.skip_empty_damage debug.hwui.skip_eglmanager_telemetry debug.hwui.early_preload_gl_context" ;;
        touch)
            echo "ro.input.resampling sys.input.resample.latency ro.surface_flinger.set_touch_timer_ms persist.input.enable_motion_prediction ro.vendor.touch.touchscheduler.enable ro.vendor.touch.touchflinger.enable persist.sys.turbosched.speed_touch.enable sys.input.touchll.mode sys.input.touchll.log vendor.perf.gestureflingboost.enable persist.sys.input.tracker.enable persist.sys.input.statistics.enable persist.debug.input.enable_input_device_usage_metrics" ;;
        gaming)
            echo "ro.surface_flinger.game_default_frame_rate_override debug.sf.use_frame_rate_priority debug.sf.disable_backpressure ro.vendor.mi_sf.144fps_duration_enable persist.sys.enable_perf_hint vendor.bluetooth.performance.game vendor.bluetooth.performance.game_ultra sys.input.touchll.mode vendor.display.enable_perf_hint_large_comp_cycle vendor.perf.game_frame_rescue vendor.display.smomo_game_support ro.vendor.mtk.gpu.game_memc persist.bluetooth.gamemode" ;;
        cust_*)
            local props=$(get_preset_props "$id")
            local keys=""
            for p in $props; do
                local k="${p%%=*}"
                keys="${keys:+$keys }$k"
            done
            echo "$keys"
            ;;
    esac
}

is_preset_active() {
    local id="$1"
    [ ! -f "$PROP_FILE" ] && return 1
    grep -qE "^[[:space:]]*#[[:space:]]*\[preset:${id}\]" "$PROP_FILE" 2>/dev/null && return 0
    if ! grep -qE "^[[:space:]]*#[[:space:]]*\[preset:" "$PROP_FILE" 2>/dev/null; then
        case "$id" in
            vulkan|hwui|sf)
                [ "$(get_module_val debug.hwui.renderer)" = "skiavk" ] && return 0
                [ "$(get_module_val vendor.debug.renderengine.backend)" = "skiavk" ] && return 0
                [ "$(get_module_val ro.hwui.use_vulkan)" = "true" ] && return 0
                ;;
            smooth)
                [ "$(get_module_val debug.sf.enable_cached_set_render_scheduling)" = "1" ] && return 0
                [ "$(get_module_val debug.sf.auto_latch_unsignaled)" = "1" ] && return 0
                [ "$(get_module_val debug.sf.latch_unsignaled)" = "1" ] && return 0
                ;;
            touch)
                [ "$(get_module_val ro.input.resampling)" = "1" ] && return 0
                [ "$(get_module_val ro.surface_flinger.set_touch_timer_ms)" = "200" ] && return 0
                ;;
            gaming)
                [ "$(get_module_val debug.sf.use_frame_rate_priority)" = "1" ] && return 0
                [ "$(get_module_val ro.surface_flinger.game_default_frame_rate_override)" = "0" ] && return 0
                ;;
        esac
    fi
    return 1
}

check_preset_conflicts() {
    local id="$1"
    local props=""
    if [ "$id" = "all" ]; then
        for p in $PRESETS_ALL; do
            props="$props $(get_preset_props "$p")"
        done
    else
        props="$(get_preset_props "$id")"
    fi

    [ -z "$props" ] && return 0

    local conflicts_found=0
    for line in $props; do
        [ -z "$line" ] && continue
        local prop="${line%%=*}"
        local our_val="${line#*=}"
        local match="" their_val="" mod_desc=""

        if [ -f "$CACHE_MODS" ]; then
            match=$(grep -E "^${prop}=" "$CACHE_MODS" 2>/dev/null | grep -v 'overridify' | head -n 1)
            if [ -n "$match" ]; then
                their_val="${match#*=}"; their_val="${their_val%\|*}"
                mod_desc="${match##*\|}"
                echo "$prop|$our_val|$mod_desc|$their_val"
                conflicts_found=1
                continue
            fi
        fi

        if [ -f "$CACHE_SCRIPTS" ]; then
            match=$(grep -m 1 -E "(resetprop|setprop).*([[:space:]]|\"|')${prop}([[:space:]]|\"|'|=)" "$CACHE_SCRIPTS" 2>/dev/null)
            if [ -n "$match" ]; then
                local s_mod="${match##*\|}"
                if [ "$s_mod" != "overridify" ]; then
                    mod_desc="module ($s_mod script)"
                    echo "$prop|$our_val|$mod_desc|script"
                    conflicts_found=1
                    continue
                fi
            fi
        fi
    done

    [ "$conflicts_found" -eq 1 ] && return 1
    return 0
}

print_preset_conflicts() {
    local id="$1"
    local raw_conflicts
    raw_conflicts=$(check_preset_conflicts "$id")
    if [ -z "$raw_conflicts" ]; then
        echo -e "${C_GREEN}${TXT_CONFLICT_NONE:-[+] No conflicts found with other active modules.}${C_RESET}"
        return 0
    fi

    echo -e "${C_YELLOW}${TXT_CONFLICT_WARN:-[!] Warning: Property conflicts with Magisk/KSU modules:}${C_RESET}"
    echo "$raw_conflicts" | while IFS='|' read -r prop our_val mod_desc their_val; do
        [ -z "$prop" ] && continue
        echo -e "  ${C_RED}*${C_RESET} ${C_BOLD}$prop${C_RESET}"
        echo -e "    ${C_GRAY}├─${C_RESET} ${TXT_CONFLICT_MOD:-Module}:      ${C_YELLOW}$mod_desc${C_RESET}"
        echo -e "    ${C_GRAY}├─${C_RESET} ${TXT_CONFLICT_THEIR:-Module val}:  ${C_RED}$their_val${C_RESET}"
        echo -e "    ${C_GRAY}└─${C_RESET} ${TXT_CONFLICT_OUR:-Preset val}:  ${C_GREEN}$our_val${C_RESET}"
    done
    return 1
}

apply_preset() {
    local id="$1"
    mkdir -p "$(dirname "$PROP_FILE")" 2>/dev/null
    [ ! -s "$PROP_FILE" ] && echo "# Overridify system.prop" > "$PROP_FILE"

    remove_preset "$id" 1

    echo "" >> "$PROP_FILE"
    echo "# [preset:${id}]" >> "$PROP_FILE"

    local props=$(get_preset_props "$id")
    for line in $props; do
        [ -z "$line" ] && continue
        local pk="${line%%=*}"
        local pv="${line#*=}"
        sed -i "/^[[:space:]]*${pk}=/d" "$PROP_FILE" 2>/dev/null
        echo "$line" >> "$PROP_FILE"
        if [ -n "$RESETPROP_BIN" ] && [ "$(id -u)" = "0" ]; then
            $RESETPROP_BIN -n "$pk" "$pv" 2>/dev/null
        fi
    done
    sed -i '/^$/N;/^\n$/D' "$PROP_FILE" 2>/dev/null
    invalidate_presets_runtime_cache
}

revert_property_to_stock() {
    local k="$1"
    [ -z "$RESETPROP_BIN" ] || [ "$(id -u)" != "0" ] && return 0
    local stock_val=""
    if [ -n "$CACHE_BUILDPROP" ] && [ -f "$CACHE_BUILDPROP" ]; then
        stock_val=$(grep -m 1 "^${k}=" "$CACHE_BUILDPROP" 2>/dev/null | cut -d= -f2 | cut -d'|' -f1)
    fi
    if [ -n "$stock_val" ]; then
        $RESETPROP_BIN -n "$k" "$stock_val" 2>/dev/null
    else
        $RESETPROP_BIN -d "$k" 2>/dev/null
    fi
}

remove_preset() {
    local id="$1"
    local quiet_cache="${2:-0}"
    [ ! -f "$PROP_FILE" ] && return 0

    [ "$id" = "vulkan" ] && [ "$quiet_cache" -eq 0 ] && remove_mali_guard_patch

    sed -i "/^[[:space:]]*#[[:space:]]*\[preset:${id}\]/d" "$PROP_FILE" 2>/dev/null

    local other_active_props=""
    for other in $(get_supported_presets) $(get_custom_presets); do
        [ "$other" = "$id" ] && continue
        if is_preset_active "$other"; then
            local op="$(get_preset_props "$other" 2>/dev/null)"
            [ -n "$op" ] && other_active_props="${other_active_props}${op}"$'\n'
        fi
    done

    local keys=$(get_preset_cleanup_keys "$id")
    for k in $keys; do
        if [ -n "$other_active_props" ] && echo "$other_active_props" | grep -qE "^${k}="; then
            continue
        fi
        sed -i "/^[[:space:]]*${k}=/d" "$PROP_FILE" 2>/dev/null
        [ "$quiet_cache" -eq 0 ] && revert_property_to_stock "$k"
    done
    sed -i '/^$/N;/^\n$/D' "$PROP_FILE" 2>/dev/null
    [ ! -s "$PROP_FILE" ] && echo "# Overridify system.prop" > "$PROP_FILE"
    [ "$quiet_cache" -eq 0 ] && invalidate_presets_runtime_cache
}

reset_all_presets() {
    [ ! -f "$PROP_FILE" ] && return 0
    local all_p="$PRESETS_ALL $(get_custom_presets)"
    for id in $all_p; do
        is_preset_active "$id" && remove_preset "$id" 1
        for k in $(get_preset_cleanup_keys "$id"); do
            revert_property_to_stock "$k"
        done
    done
    remove_mali_guard_patch
    echo "# Overridify system.prop" > "$PROP_FILE"
    invalidate_presets_runtime_cache
}

save_custom_preset() {
    local id="$1" name="$2" desc="$3" props="$4"
    mkdir -p "$CUSTOM_PRESETS_DIR" 2>/dev/null
    local f="$CUSTOM_PRESETS_DIR/${id}.conf"
    {
        echo "name=$name"
        echo "desc=$desc"
        echo "# Properties"
        echo "$props" | grep -v '^[[:space:]]*#' | grep '=' | grep -v '^name=' | grep -v '^desc='
    } > "$f" 2>/dev/null
    invalidate_presets_runtime_cache
}

delete_custom_preset() {
    local id="$1"
    local f="$CUSTOM_PRESETS_DIR/${id}.conf"
    if [ -f "$f" ]; then
        if is_preset_active "$id"; then
            remove_preset "$id"
        fi
        rm -f "$f" 2>/dev/null
        invalidate_presets_runtime_cache
        return 0
    fi
    return 1
}

export_custom_preset_cipher() {
    local id="$1"
    local f="$CUSTOM_PRESETS_DIR/${id}.conf"
    [ ! -f "$f" ] && return 1
    local payload
    payload=$(gzip -c "$f" 2>/dev/null | base64 | tr -d '\r\n')
    echo "OVRD1:${payload}"
}

export_all_custom_presets_cipher() {
    [ ! -d "$CUSTOM_PRESETS_DIR" ] && return 1
    local nl='
'
    local combined=""
    for f in "$CUSTOM_PRESETS_DIR"/cust_*.conf; do
        [ -f "$f" ] || continue
        local c=$(cat "$f")
        [ -n "$combined" ] && combined="${combined}${nl}===PRESET===${nl}${c}" || combined="===PRESET===${nl}${c}"
    done
    [ -z "$combined" ] && return 1
    local payload
    payload=$(printf "%s" "$combined" | gzip -c 2>/dev/null | base64 | tr -d '\r\n')
    echo "OVRD1:${payload}"
}

import_custom_preset_cipher() {
    local cipher="$1"
    cipher=$(echo "$cipher" | tr -d '[:space:]')
    case "$cipher" in
        OVRD1:*) ;;
        *) return 1 ;;
    esac
    local payload="${cipher#OVRD1:}"
    local content
    content=$(printf "%s" "$payload" | base64 -d 2>/dev/null | gzip -dc 2>/dev/null || printf "%s" "$payload" | base64 -d 2>/dev/null)
    [ -z "$content" ] && return 2

    mkdir -p "$CUSTOM_PRESETS_DIR" 2>/dev/null

    if echo "$content" | grep -q "===PRESET==="; then
        local nl='
'
        local p_cnt=0
        local cur_block=""
        local tmp_pack="$OVER_TMP_DIR/import_pack.tmp"
        printf "%s\n" "$content" > "$tmp_pack" 2>/dev/null
        while IFS= read -r line || [ -n "$line" ]; do
            if [ "$line" = "===PRESET===" ]; then
                if [ -n "$cur_block" ]; then
                    local p_name=$(echo "$cur_block" | grep -m 1 "^name=" | cut -d= -f2-)
                    [ -z "$p_name" ] && p_name="Preset $((p_cnt + 1))"
                    local slug=$(echo "$p_name" | tr -cd 'a-zA-Z0-9_' | tr 'A-Z' 'a-z')
                    [ -z "$slug" ] && slug="preset"
                    local pid="cust_${slug}_$(date +%s)_${p_cnt}"
                    echo "$cur_block" > "$CUSTOM_PRESETS_DIR/${pid}.conf" 2>/dev/null
                    p_cnt=$((p_cnt + 1))
                    cur_block=""
                fi
            else
                [ -n "$cur_block" ] && cur_block="${cur_block}${nl}${line}" || cur_block="$line"
            fi
        done < "$tmp_pack"
        rm -f "$tmp_pack" 2>/dev/null

        if [ -n "$cur_block" ]; then
            local p_name=$(echo "$cur_block" | grep -m 1 "^name=" | cut -d= -f2-)
            [ -z "$p_name" ] && p_name="Preset $((p_cnt + 1))"
            local slug=$(echo "$p_name" | tr -cd 'a-zA-Z0-9_' | tr 'A-Z' 'a-z')
            [ -z "$slug" ] && slug="preset"
            local pid="cust_${slug}_$(date +%s)_${p_cnt}"
            echo "$cur_block" > "$CUSTOM_PRESETS_DIR/${pid}.conf" 2>/dev/null
            p_cnt=$((p_cnt + 1))
        fi

        invalidate_presets_runtime_cache
        echo "PACK:$p_cnt"
        return 0
    fi

    local name=$(echo "$content" | grep -m 1 "^name=" | cut -d= -f2-)
    [ -z "$name" ] && name="Imported Preset"

    local slug=$(echo "$name" | tr -cd 'a-zA-Z0-9_' | tr 'A-Z' 'a-z')
    [ -z "$slug" ] && slug="preset"
    local id="cust_${slug}_$(date +%s)"
    local out="$CUSTOM_PRESETS_DIR/${id}.conf"
    echo "$content" > "$out" 2>/dev/null
    invalidate_presets_runtime_cache
    echo "$id"
    return 0
}