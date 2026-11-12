#!/system/bin/sh
# ==============================================================================
# Overridify — Списки целевых файлов для аудита подсистем (Audit Targets Registry)
# ==============================================================================
# В этом файле задаются списки нативных библиотек (.so), системных бинарников (bin)
# и JAR-файлов фреймворка для аудита каждой подсистемы и для Полного аудита.
#
# КАК ДОБАВИТЬ НОВЫЙ ФАЙЛ ДЛЯ АУДИТА:
# 1. Найдите нужную категорию (например, TARGETS_HWUI, TARGETS_AUDIO, TARGETS_OEM_DISP).
# 2. Допишите путь к файлу в список (каждый файл с новой строки или через пробел).
# 3. При следующем аудите или поиске Overridify автоматически включит его в анализ!
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. HWUI 2D Rendering Engine (Skia GL / Vulkan)
# ------------------------------------------------------------------------------
TARGETS_HWUI="
    /system/lib64/libhwui.so
    /system_ext/lib64/libhwui*.so
    /system_ext/lib64/libhwuiextimpl.so
    /system_ext/lib64/liboplushwui_jni.so
"

# ------------------------------------------------------------------------------
# 2. SurfaceFlinger & RenderEngine (Композитор и отрисовка слоев)
# ------------------------------------------------------------------------------
TARGETS_SF="
    /system/bin/surfaceflinger
    /system_ext/bin/surfaceflinger
    /system*/lib64/libsurfaceflinger*.so
    /system*/lib64/libSurfaceFlingerProp.so
    /system*/lib64/librenderengine*.so
    /system*/lib64/libgui*.so
    /system*/lib64/libui.so
    /system_ext/lib64/libmisurfaceflinger.so
    /system_ext/lib64/librenderengineextimpl.so
    /system_ext/lib64/libguiextimpl.so
    /system_ext/lib64/libgpuserviceextimpl.so
    /system_ext/lib64/libvulkanextimpl.so
    /system_ext/lib64/libeglextimpl.so
    /system_ext/lib64/liboplus_display_watchcall.so
    /system_ext/lib64/libcomposerextn.qti.so
    /vendor/lib64/libsf_*.so
    /vendor/lib64/libdisp_dejitter*.so
    /vendor/lib64/libmtk_sf_*.so
"

# ------------------------------------------------------------------------------
# 3. Display HAL & Gralloc (Графический контроллер и аллокатор памяти)
# ------------------------------------------------------------------------------
TARGETS_DISP="
    /vendor/bin/hw/vendor.qti.hardware.display.composer-service
    /vendor/bin/hw/android.hardware.graphics.composer3-service
    /vendor/lib64/libgralloccore.so
    /vendor/bin/hw/vendor.qti.hardware.display.allocator-service
    /vendor/bin/hw/vendor.display.color@1.0-service
    /vendor/lib64/libsdmcore.so
    /vendor/lib64/libsdmextension.so
    /vendor/lib64/libsdmutils.so
    /vendor/lib64/libsdmdal.so
    /vendor/lib64/libdigital-dimming.so
    /system_ext/lib64/libcomposerextn.qti.so
    /system*/bin/surfaceflinger
    /system*/lib64/libsurfaceflinger*.so
    /system*/lib64/libgui*.so
    /vendor/lib64/libdisplayfeature*.so
    /vendor/bin/hw/android.hardware.graphics.allocator@*-service-mediatek*
    /vendor/bin/hw/vendor.mediatek.hardware.pq@*-service
    /vendor/bin/hw/vendor.mediatek.hardware.mms@*-service
    /vendor/bin/hw/vendor.xiaomi.hardware.displayfeature*
    /vendor/lib64/hw/*/android.hardware.graphics.allocator*
    /vendor/lib64/hw/*/gralloc.*.so
    /vendor/lib64/libged.so
    /vendor/lib64/libpq_prot.so
    /vendor/lib64/libpqframework.so
"

# ------------------------------------------------------------------------------
# 4. Audio Pipeline (AOSP Core, AudioFlinger, AudioPolicy & Qualcomm HAL/PAL)
# ------------------------------------------------------------------------------
TARGETS_AUDIO="
    /system/lib64/libaudioflinger.so
    /system/lib64/libaudioflinger_utils.so
    /system/lib64/libaudioprocessing.so
    /system/lib64/libaudiopolicyservice.so
    /system/lib64/libaudiopolicymanagerdefault.so
    /system/lib64/libaudiopolicycomponents.so
    /system/lib64/libaudiopolicyenginedefault.so
    /system/lib64/libaudioclient.so
    /system/lib64/libaaudio.so
    /system/lib64/libaudiofoundation.so
    /system/lib64/libaudio-resampler.so
    /system/lib64/libmediautils.so
    /system/lib64/libmediaplayerservice.so
    /system/lib64/libaudiohal@aidl.so
    /system_ext/lib64/libavenhancements.so
    /system_ext/lib64/liboplusaudiopcmdump.so
    /system_ext/lib64/libaudioclientextimpl.so
    /system_ext/lib64/libaudioflingerextimpl.so
    /system_ext/lib64/libaudiopolicyextimpl.so
    /system_ext/lib64/libaudioprocessingextimpl.so
    /system_ext/lib64/libaaudioserviceextimpl.so
    /vendor/lib64/hw/audio.primary.*.so
    /vendor/lib64/libar-pal.so
    /vendor/lib64/libagm.so
    /vendor/lib64/libadm.so
    /vendor/lib64/libavenhancements.so
    /vendor/lib64/liblx-osal.so
    /vendor/lib64/soundfx/libqcompostprocbundle.so
    /vendor/lib64/soundfx/libvolumelistener.so
    /vendor/lib64/libqc2audio_swaudiocodec.so
    /vendor/lib64/libqc2audio_hwaudiocodec.so
    /vendor/lib64/libqc2audio_core.so
    /vendor/lib64/libqc2audio_utils.so
    /vendor/bin/hw/android.hardware.audio.service.mediatek
    /vendor/lib64/hw/android.hardware.audio@*-impl-mediatek.so
    /vendor/lib64/android.hardware.audio.service-mediatek.so
"

# ------------------------------------------------------------------------------
# 5. Dolby Atmos Engine (Пространственный звук и эквалайзер)
# ------------------------------------------------------------------------------
TARGETS_DOLBY="
    /odm/lib64/libdapparamstorage*.so
    /vendor/lib64/libdapparamstorage*.so
    /odm/lib64/soundfx/libswdap*.so
    /vendor/lib64/soundfx/libswdap*.so
    /vendor/lib64/soundfx/libswgamedap*.so
    /vendor/lib64/soundfx/libswspatializer.so
    /odm/bin/hw/vendor.dolby*
    /vendor/bin/hw/vendor.dolby*
    /odm/lib64/vendor.dolby*
    /vendor/lib64/vendor.dolby*
    /odm/bin/hw/dvs-hal-service
    /odm/bin/hw/dolbycodec2
    /vendor/lib64/libdolby*.so
    /system_ext/lib64/libcodecextimpl.so
"

# ------------------------------------------------------------------------------
# 6. Bluetooth & LE Audio (Стек BT, кодеки aptX/LDAC/LC3, аппаратный оффлоад)
# ------------------------------------------------------------------------------
TARGETS_BT="
    /system/lib64/libbluetooth_jni.so
    /system/app/Bluetooth/lib/arm64/libbluetooth_jni.so
    /system/app/Bluetooth/lib/arm64/liboplusbluetooth_jni.so
    /apex/com.android.btservices/lib64/libbluetooth_jni.so
    /apex/com.android.btservices/app/*/*.apk
    /system/lib64/android.hardware.bluetooth.audio-V3-ndk.so
    /system/lib64/libaudiopolicycomponents.so
    /system/lib64/libaudiopolicyenginedefault.so
    /vendor/lib64/hw/android.hardware.bluetooth.audio-impl-qti.so
    /vendor/lib64/libbluetooth_audio_session.so
    /vendor/lib64/btaudio_offload_if.so
    /vendor/lib64/hw/vendor.qti.hardware.bluetooth_audio@2.1-impl.so
    /vendor/lib64/hw/vendor.qti.hardware.bluetooth_sar@1.1-impl.so
    /vendor/lib64/hw/android.hardware.bluetooth@1.0-impl-qti.so
    /vendor/lib64/hw/android.hardware.bluetooth@1.1-impl-qti.so
    /vendor/bin/hw/android.hardware.bluetooth@1.1-service-qti
    /vendor/bin/hw/android.hardware.bluetooth@*-service-mediatek
    /vendor/lib64/hw/android.hardware.bluetooth@*-impl-mediatek.so
"

# ------------------------------------------------------------------------------
# 7. Input & Frame Pacing (Обработка касаний, задержка ввода и планировщик)
# ------------------------------------------------------------------------------
TARGETS_INPUT="
    /system*/lib64/libinput*.so
    /system*/lib64/libtouch*.so
    /system_ext/lib64/libmiinput*.so
    /system_ext/lib64/libdolphin.so
    /system_ext/lib64/libinputextensionsimpl.so
    /system_ext/lib64/libinputflingerextimpl.so
    /system_ext/lib64/libpenguin_impl.so
    /vendor/bin/hw/vendor.qti.hardware.perf-hal-service
    /vendor/lib64/libqti-perfd-client.so
"

# ------------------------------------------------------------------------------
# 8. OEM Audio Pipeline (ColorOS / MIUI / HyperOS)
# ------------------------------------------------------------------------------
TARGETS_OEM_AUDIO="
    /system/lib64/libaudioflinger.so
    /system/lib64/libaudiopolicyservice.so
    /system/lib64/libaudiopolicycomponents.so
    /system/lib64/libaudiopolicyenginedefault.so
    /system_ext/lib64/libaudioflingerextimpl.so
    /system_ext/lib64/libaudiopolicyextimpl.so
    /system_ext/lib64/libaudioclientextimpl.so
    /system_ext/lib64/libaudioprocessingextimpl.so
    /system_ext/lib64/libaaudioserviceextimpl.so
    /system_ext/lib64/liboplusMetaAudio.so
    /system_ext/lib64/liboplusaudioDump.so
    /system_ext/lib64/libOplusAudioFade.so
    /system_ext/lib64/vendor.oplus.hardware.bluetooth_audio_extend@2.1.so
    /odm/lib64/hw/audio.binaural_record.default.so
    /odm/lib64/soundfx/liboplusMssEffects.so
    /odm/lib64/vendor.oplus.hardware.binaural_record-V1-ndk.so
    /odm/lib64/hw/vendor.oplus.hardware.binaural_record-impl.so
    /odm/lib64/libbinaural_record_session_aidl.so
    /odm/lib64/vendor.oplus.hardware.virtual_device.audio-V1-ndk.so
    /vendor/lib64/soundfx/libmisound.so
    /system_ext/lib64/libmisound.so
"

# ------------------------------------------------------------------------------
# 9. OEM Display & Touch (Управление панелью, калибровка цвета, тачскрин)
# ------------------------------------------------------------------------------
TARGETS_OEM_DISP="
    /odm/bin/hw/vendor.oplus.hardware.displaypanelfeature@1.0-service
    /odm/bin/hw/vendor.oplus.hardware.mmdisplayfeature@1.0-service
    /odm/bin/hw/vendor-oplus-hardware-touch-V2-service
    /odm/bin/touchDaemon
    /vendor/lib64/libcwb_qcom.so
    /odm/bin/cwb_utils
    /odm/lib64/vendor.oplus.hardware.displaypanelfeature@1.0.so
    /odm/lib64/vendor.oplus.hardware.mmdisplayfeature@1.0.so
    /odm/lib64/vendor.oplus.hardware.touch-V1-ndk.so
    /odm/lib64/vendor.oplus.hardware.touch-V2-ndk.so
    /odm/lib64/libclstc_fodcolor_csc.so
    /odm/lib64/libPanelChaplin.so
    /odm/lib64/vendor.oplus.hardware.display.MixLut3D-V1-ndk.so
    /system_ext/lib64/liboplusdisplaycolormanager.so
    /system_ext/lib64/liboplus_display_watchcall.so
    /system_ext/lib64/liboplus_display_input.so
    /system_ext/lib64/libcomposerextn.qti.so
    /system_ext/lib64/vendor.oplus.hardware.displaypanelfeature@1.0.so
    /system_ext/lib64/vendor.oplus.hardware.touch-V2-ndk.so
    /system_ext/lib64/vendor.oplus.hardware.touch@1.0.so
    /system_ext/lib64/libtouch*
    /system_ext/lib64/libmiinput*
    /vendor/lib64/libdisplayfeature*.so
    /vendor/bin/hw/vendor.xiaomi.hardware.displayfeature*
"

# ------------------------------------------------------------------------------
# 10. OEM Performance & Gaming (Игровые оптимизаторы, планировщики потоков)
# ------------------------------------------------------------------------------
TARGETS_OEM_PERF="
    /system_ext/bin/oiface
    /system_ext/bin/horae
    /system_ext/bin/perfservice
    /odm/bin/hw/vendor-oplus-hardware-performance-V1-service
    /odm/bin/hw/vendor.oplus.hardware.gameopt-service
    /odm/bin/hw/vendor.oplus.hardware.urcc-service
    /odm/bin/hw/vendor.oplus.hardware.ormsHalService-aidl-service
    /vendor/bin/hw/vendor.qti.hardware.perf-hal-service
    /vendor/bin/hw/vendor.qti.hardware.iop@2.0-service
    /vendor/lib64/libqti-perfd.so
    /vendor/lib64/libqti-iopd.so
    /vendor/lib64/libperfconfig.so
    /odm/lib64/vendor.oplus.hardware.performance-V1-ndk.so
    /odm/lib64/vendor.oplus.hardware.performance-V2-ndk.so
    /odm/lib64/vendor.oplus.hardware.osense.client-V1-ndk.so
    /odm/lib64/vendor.oplus.hardware.urcc-V1-ndk.so
    /odm/lib64/vendor.oplus.hardware.ormsHalService-V1-ndk.so
    /odm/lib64/vendor.oplus.hardware.orms@1.0.so
    /odm/lib64/vendor.oplus.hardware.gameopt-V1-ndk.so
    /odm/lib64/liburcccore.so
    /odm/lib64/libosenseaidlhalclient.so
    /odm/lib64/liboplus-uah-client.so
    /odm/lib64/libuahcore.so
    /odm/lib64/libormshalclient.so
    /odm/lib64/libSchedAssistExtImpl_vendor.so
    /system_ext/lib64/libSchedAssistExtImpl.so
    /system_ext/lib64/libSchedAssistJni.so
    /system_ext/lib64/libQosSched_Jni.so
    /system_ext/lib64/libUahPerf_Jni.so
    /system_ext/lib64/qos_sched.so
    /system_ext/lib64/vendor.oplus.hardware.gameinference-V1-ndk.so
    /vendor/bin/hw/vendor.mediatek.hardware.mtkpower@*-service
    /vendor/bin/hw/vendor.xiaomi.hardware.miperf@*-service
    /vendor/bin/hw/vendor.mediatek.hardware.nwk_opt@*-service
    /system_ext/bin/hyper_bpfloader
    /system_ext/bin/miuitcptracker
"

# ------------------------------------------------------------------------------
# 11. OEM Haptics & Vibration (Тактильный отклик, вибромоторы Richtap/AAC)
# ------------------------------------------------------------------------------
TARGETS_OEM_HAPTIC="
    /vendor/bin/hw/vendor.qti.hardware.vibrator.service
    /vendor/lib64/vendor.qti.hardware.vibrator.impl.so
    /vendor/lib64/vendor.oplus.hardware.oplusvibrator-V1-ndk.so
    /vendor/lib64/vendor.oplus.hardware.vibrator-V1-ndk.so
    /vendor/lib64/vendor.aac.hardware.richtap.vibrator-V2-ndk.so
    /vendor/lib64/libaacvibrator.so
    /vendor/lib64/libsivibrator.so
"

# ------------------------------------------------------------------------------
# 12. OEM Camera & Media (Модули камеры, пост-обработка Midas/Chi)
# ------------------------------------------------------------------------------
TARGETS_OEM_CAM="
    /odm/bin/hw/vendor.oplus.hardware.cammidasservice-V1-service
    /odm/bin/hw/virtualcameraprovider
    /odm/lib64/hw/camera.oemlayer.so
    /vendor/lib64/hw/camera.qcom.so
    /vendor/lib64/hw/com.qti.chi.override.so
    /vendor/lib64/libcamxcommonutils.so
    /vendor/lib64/libchifeature2.so
    /vendor/lib64/libhwconfigurationutil.so
    /odm/lib64/libextensionlayer.so
    /odm/lib64/libhwconfigurationutil.so
    /vendor/lib64/vendor.oplus.hardware.cameraextension-V1-ndk.so
    /odm/lib64/vendor.oplus.hardware.cammidasservice-V1-ndk.so
    /odm/lib64/vendor.oplus.hardware.camera_rfi-V1-ndk.so
    /odm/lib64/vendor.oplus.hardware.cameraextension-V1-service-impl.so
    /odm/lib64/vendor.oplus.hardware.engcamera@1.0.so
    /odm/lib64/vendor.oplus.hardware.extcamera@1.0.so
    /odm/lib64/vendor.oplus.hardware.sendextcamcmd-V1-service-impl.so
    /system_ext/lib64/vendor.oplus.hardware.virtual_device.camera.manager@1.0.so
    /system_ext/lib64/vendor.oplus.hardware.midasdev@1.0.so
    /system_ext/lib64/vendor.oplus.hardware.cameraMDM@1.0.so
"

# ------------------------------------------------------------------------------
# 13. OEM System, Power & Framework (Контроллеры питания, зарядки и стабильности)
# ------------------------------------------------------------------------------
TARGETS_OEM_SYS="
    /odm/bin/hw/vendor.oplus.hardware.charger-V9-service
    /odm/bin/hw/vendor.oplus.hardware.charger-V1-service
    /odm/bin/hw/vendor.oplus.hardware.rpmh-V1-service
    /odm/bin/hw/android.hardware.power.stats-impl.oplus
    /odm/bin/hw/vendor-oplus-hardware-power-powermonitor-V1-service
    /odm/lib64/vendor.oplus.hardware.charger-V9-ndk.so
    /odm/lib64/vendor.oplus.hardware.charger@1.0.so
    /odm/lib64/vendor.oplus.hardware.rpmh-V1-ndk.so
    /odm/lib64/vendor.oplus.hardware.power.powermonitor-V1-ndk.so
    /system_ext/lib64/vendor.oplus.hardware.charger-V9-ndk.so
    /system_ext/lib64/vendor.oplus.hardware.charger@1.0.so
    /system/bin/lmkd
    /system_ext/bin/olc
    /system_ext/bin/osvelte
    /system_ext/bin/phoenix_log_manager
    /system_ext/bin/oplus_gaia
    /system_ext/bin/oplus_kevent
    /system_ext/bin/oplus_last_boot_reason
    /system_ext/bin/hans
    /system_ext/bin/oplus_theia
    /system_ext/bin/theia_screen_monitor
    /system_ext/bin/oplusHmbirdBpfManager
    /system_ext/bin/ostatsd
    /system_ext/bin/ostats_pullerd
    /system_ext/bin/ostats_tpd
    /system_ext/bin/criticallog
    /system_ext/bin/oplus_abnormal_reboot_record
    /system_ext/bin/ordump_ctrl
    /system_ext/bin/minidumpreader
    /system_ext/bin/oplus_defrag
    /system_ext/lib64/liboplusextstability.so
    /system_ext/lib64/liboplusextproperty.so
    /system_ext/lib64/liboplusbindermonitor.so
    /system_ext/lib64/liboplusdcs.so
    /system_ext/lib64/libquickboot.so
    /system_ext/lib64/libitheiaservice.so
    /system_ext/lib64/lib_theiaDumpstateEx.so
    /system_ext/lib64/libtheia_jni.so
    /system_ext/lib64/liboplus_bpf_jni.so
    /system_ext/lib64/libobpf_connection.so
    /odm/bin/hw/vendor.oplus.hardware.stability.oplus_project-V1-service
    /odm/bin/hw/vendor-oplus-hardware-engineer-V1-service
    /vendor/bin/mi_thermald
    /vendor/bin/hw/android.hardware.thermal@*-service.mtk
    /vendor/bin/fuelgauged*
    /odm/bin/hw/vendor.oplus.hardware.cryptoeng@1.0-service
    /odm/bin/hw/vendor.oplus.hardware.biometrics.fingerprint@2.1-service_uff
    /odm/bin/hw/vendor.oplus.hardware.biometrics.face@1.0-service
    /odm/bin/hw/vendor.oplus.hardware.biometrics.fingerprintpay@1.0-service
    /odm/lib64/vendor.oplus.hardware.stability.oplus_project-V2-ndk.so
    /odm/lib64/vendor.oplus.hardware.subsys-V5-ndk.so
    /odm/lib64/vendor.oplus.hardware.subsys_radio-V8-ndk.so
    /odm/lib64/libsubsys-service.so
    /odm/lib64/libqti-subsys-service.so
    /system_ext/lib64/libtheia_client.so
    /system_ext/lib64/libostatsd_client.so
    /system_ext/lib64/libhmbird_client.so
    /odm/lib64/libcharger_client.so
    /odm/lib64/librpmh_client.so
    /system_ext/lib64/libopluspowerclient.so
    /system_ext/lib64/liboplus_battery.so
    /system_ext/lib64/liboplus_charger.so
    /system_ext/lib64/libsupervooc.so
"

# ------------------------------------------------------------------------------
# 14. Базовые системные демоны и библиотеки AOSP (для Полного аудита)
# ------------------------------------------------------------------------------
TARGETS_GLOBAL_BINS="
    /system/lib64/libc.so
    /system/lib64/libbinder.so
    /system/lib64/libutils.so
    /system/lib64/libcutils.so
    /system/lib64/libbase.so
    /system/lib64/libandroid_runtime.so
    /system/lib64/libmedia.so
    /system/bin/init
    /system/bin/app_process64
    /system/bin/audioserver
    /system/bin/cameraserver
    /system/bin/mediaserver
    /system/bin/netd
    /system/bin/vold
    /system/bin/installd
    /system/bin/keystore2
    /vendor/bin/hw/*
    /odm/bin/hw/*
"

# ------------------------------------------------------------------------------
# 15. Системные и OEM JAR-архивы и APK (байткод-индексатор Dalvik/ART dexdump)
# ------------------------------------------------------------------------------
TARGETS_FW_JARS="
    /system/framework/*.jar
    /system_ext/framework/*.jar
    /product/framework/*.jar
    /product/*/system/framework/*.jar
    /vendor/framework/*.jar
    /odm/framework/*.jar
    /oem/framework/*.jar
    /mi_ext/*/framework/*.jar
    /my_product/framework/*.jar
    /apex/*/javalib/*.jar
    /system/app/*/*.apk
    /system/priv-app/*/*.apk
    /system_ext/app/*/*.apk
    /system_ext/priv-app/*/*.apk
    /product/app/*/*.apk
    /product/priv-app/*/*.apk
    /vendor/app/*/*.apk
    /vendor/priv-app/*/*.apk
    /mi_ext/*/app/*/*.apk
    /mi_ext/*/priv-app/*/*.apk
"

# ------------------------------------------------------------------------------
# 16. Модули APEX (ART Runtime, Media, Codecs, Bionic, Resolv, Statsd)
# ------------------------------------------------------------------------------
TARGETS_APEX_BINS="
    /apex/com.android.art/bin/*
    /apex/com.android.art/lib64/*
    /apex/com.android.runtime/lib64/*
    /apex/com.android.media/lib64/*
    /apex/com.android.media.swcodec/lib64/*
    /apex/com.android.os.statsd/bin/*
    /apex/com.android.resolv/lib64/*
    /apex/com.android.adbd/bin/*
    /apex/com.android.btservices/lib64/*
    /apex/com.android.tethering/bin/*
"

# ==============================================================================
# Вспомогательные функции получения списков существующих файлов
# ==============================================================================

# Получить все уникальные существующие нативные бинарники и библиотеки
get_all_target_bins() {
    local all_raw="
        $TARGETS_HWUI
        $TARGETS_SF
        $TARGETS_DISP
        $TARGETS_AUDIO
        $TARGETS_DOLBY
        $TARGETS_BT
        $TARGETS_INPUT
        $TARGETS_OEM_AUDIO
        $TARGETS_OEM_DISP
        $TARGETS_OEM_PERF
        $TARGETS_OEM_HAPTIC
        $TARGETS_OEM_CAM
        $TARGETS_OEM_SYS
        $TARGETS_GLOBAL_BINS
        $TARGETS_APEX_BINS
    "
    local res=""
    for item in $all_raw; do
        case "$item" in
            *.jar|*.apk|*"@"*) continue ;;
            *"*"*)
                for f in $item; do
                    case "$f" in *"@"*) continue ;; esac
                    [ -f "$f" ] && res="$res $f"
                done
                ;;
            *)
                case "$item" in *"@"*) continue ;; esac
                [ -f "$item" ] && res="$res $item"
                ;;
        esac
    done
    echo "$res" | tr ' ' '\n' | sort -u | tr '\n' ' '
}

# Получить все уникальные существующие корни разделов (исключая псевдо-ФС, пользовательские данные и bloatware)
get_fw_roots() {
    local roots=""
    for d in /*; do
        [ -d "$d" ] || continue
        case "$d" in
            /proc|/sys|/dev|/data|/data_mirror|/storage|/sdcard|/mnt|/apex|/config|/metadata|/lost+found|/tmp|/linkerconfig|/bugreports|/debug_ramdisk|/bootstrap-apex|/cust)
                continue ;;
            *)
                roots="$roots $d" ;;
        esac
    done
    echo "$roots"
}

# Получить все уникальные активные корни модулей APEX (исключая версионированные дубликаты)
get_apex_roots() {
    local aroots=""
    for a in /apex/*; do
        [ -d "$a" ] || continue
        case "$a" in *@*) continue ;; esac
        aroots="$aroots $a"
    done
    echo "$aroots"
}

# Получить все целевые JAR/APK архивы для анализа байткода через трехуровневую системную иерархию (3-Tier Source Tiering)
get_all_target_jars() {
    local roots="$(get_fw_roots)"
    local aroots="$(get_apex_roots)"

    # 1. Поиск всех системных JAR и APK (исключая оверлеи без DEX, data-app и cust-bloatware)
    local raw=$(find $roots $aroots -maxdepth 6 \( -name "*.jar" -o -name "*.apk" \) \
        ! -path "*/overlay/*" \
        ! -path "*/data-app/*" \
        ! -path "*/cust/*" 2>/dev/null)

    # 2. Трехуровневая системная архитектура (3-Tier Architecture):
    # Tier 1: Системный фреймворк и службы (JAR) — наивысший авторитет
    local t1=$(echo "$raw" | grep -E "(\.jar$|/javalib/)" | sort -u)

    # Tier 2: Все привилегированные приложения платформы и вендора (priv-app)
    # Упорядочиваем по авторитетности разделов: /system -> /system_ext -> /product -> /vendor -> остальное
    local raw_t2=$(echo "$raw" | grep -vE "(\.jar$|/javalib/)" | grep -E "/priv-app/")
    local t2_sys=$(echo "$raw_t2" | grep -E "^/system/" | sort -u)
    local t2_ext=$(echo "$raw_t2" | grep -E "^/system_ext/" | sort -u)
    local t2_prd=$(echo "$raw_t2" | grep -E "^/product/" | sort -u)
    local t2_vnd=$(echo "$raw_t2" | grep -E "^/(vendor|odm)/" | sort -u)
    local t2_rst=$(echo "$raw_t2" | grep -vE "^/(system|system_ext|product|vendor|odm)/" | sort -u)
    local t2="$t2_sys $t2_ext $t2_prd $t2_vnd $t2_rst"

    # Tier 3: Все обычные системные приложения (app)
    local raw_t3=$(echo "$raw" | grep -vE "(\.jar$|/javalib/|/priv-app/)")
    local t3_sys=$(echo "$raw_t3" | grep -E "^/system/" | sort -u)
    local t3_ext=$(echo "$raw_t3" | grep -E "^/system_ext/" | sort -u)
    local t3_prd=$(echo "$raw_t3" | grep -E "^/product/" | sort -u)
    local t3_vnd=$(echo "$raw_t3" | grep -E "^/(vendor|odm)/" | sort -u)
    local t3_rst=$(echo "$raw_t3" | grep -vE "^/(system|system_ext|product|vendor|odm)/" | sort -u)
    local t3="$t3_sys $t3_ext $t3_prd $t3_vnd $t3_rst"

    echo "$t1 $t2 $t3"
}

# Получить объединенный список всех целей аудита (ELF + JAR)
get_all_targets() {
    echo "$(get_all_target_bins) $(get_all_target_jars)"
}
