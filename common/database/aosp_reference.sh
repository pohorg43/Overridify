# ==============================================================================
# Overridify — База жизненного цикла системных свойств (AOSP & Vendor Lifecycle)
# ==============================================================================
# Назначение: Определение точных версионных границ (min_api:max_api:scope)
# для реальных свойств операционной системы, вывод из эксплуатации которых
# доказан исходными кодами AOSP / CAF / OEM.
#
# Формат метаданных: RET_META="<def_val>:<min_api>:<max_api>:<scope>"
#   def_val  — Эталонный дефолт (или 'none', если удалено/неприменимо)
#   min_api  — Версия API Android, в которой свойство было внедрено
#   max_api  — Версия API Android, в которой свойство УСТАРЕЛО (deprecated)
#              (при достижении этой версии флаг помечается как 'deprecated (Axx+)')
#   scope    — Подсистема (aosp, qti, qti_ahal, qti_rc, qti_rotator, dolby, dts)
# ==============================================================================

resolve_prop_lifecycle() {
    local prop="$1" api="$2" sub=""
    RET_META=":::"

    case "$prop" in
        # 1. Dolby Atmos / Audio Experience (DAX) & Legacy DS2
        *dolby.fade_switch*|*dolby.surround.enable*|*dolby.eq.half*|\
        *dolby.profile.default*|*dolby.dax.support*|*dolby.control.support*|\
        *dolby.dax.version*)
            RET_META="true:28:30:dolby" ;;
        *dolby.ds2.*|*dolby.ds.state*)
            RET_META="false:19:29:dolby" ;;
        persist.audio.dolby.enabled)
            RET_META="false:23:28:dolby" ;;
        ro.dolby.present)
            RET_META="true:21:28:dolby" ;;

        # 2. Legacy AOSP Core & SurfaceFlinger
        persist.sys.composition.type)
            RET_META="c2d:10:14:aosp" ;;
        debug.sf.hw)
            RET_META="0:9:21:aosp" ;;
        debug.sf.latch_unsignaled)
            RET_META="1:30:33:aosp" ;;

        # 3. HWUI Legacy Texture Caches (AOSP 9.0+ removal)
        ro.hwui.texture_cache_size|ro.hwui.layer_cache_size|ro.hwui.path_cache_size|\
        ro.hwui.drop_shadow_cache_size|ro.hwui.gradient_cache_size|ro.hwui.r_buffer_cache_size|\
        ro.hwui.texture_cache_flushrate|ro.hwui.text_large_cache_*|ro.hwui.text_small_cache_*)
            RET_META="none:14:28:aosp" ;;
        debug.hwui.skia_atrace_enabled)
            RET_META="false:31:34:aosp" ;;
        debug.hwui.renderer)
            RET_META="skiagl:28:99:aosp" ;;

        # 4. Display & QTI Architecture Boundaries
        vendor.display.disable_offline_rotator)
            RET_META="1:26:29:qti" ;;
        vendor.display.lcd_density)
            RET_META="480:21:29:qti" ;;
        vendor.display.enable_rc_support)
            RET_META="1:28:31:qti_rc" ;;
        vendor.display.disable_spec_fence)
            RET_META="none:30:31:qti" ;;
        vendor.display.enable_async_powermode)
            RET_META="0:28:33:qti" ;;

        # 5. Legacy Qualcomm Audio HAL (A11+ PAL/AIDL Migration)
        audio.offload.pcm.*)
            RET_META="true:21:30:qti_ahal" ;;
        vendor.audio.offload.pcm.*)
            RET_META="true:26:30:qti_ahal" ;;
        vendor.audio.offload.gapless.enabled|vendor.audio.offload.multiple.enabled)
            RET_META="none:19:28:aosp" ;;
        vendor.audio.feature.hdmi_edid.enable|vendor.audio.feature.hdmi_passthrough.enable|\
        vendor.audio.feature.spkr_prot.enable|vendor.audio.feature.afe_proxy.enable|\
        vendor.audio.feature.handset.profile.disable|vendor.audio.feature.a2dp_offload.enable|\
        vendor.audio.feature.battery_listener.enable|vendor.audio.feature.hfp.enable|\
        vendor.audio.feature.compress_in.enable|vendor.audio.feature.concurrent_capture.enable|\
        vendor.audio.feature.compress_meta_data.enable|vendor.audio.feature.custom_stereo.enable|\
        vendor.audio.feature.display_port.enable|vendor.audio.feature.dynamic_ecns.enable|\
        vendor.audio.feature.extn_flac_decoder.enable|vendor.audio.feature.extn_formats.enable|\
        vendor.audio.feature.extn_resampler.enable|vendor.audio.feature.fm.enable|\
        vendor.audio.feature.hifi_audio.enable|vendor.audio.feature.incall_music.enable|\
        vendor.audio.feature.keep_alive.enable|vendor.audio.feature.multi_voice_session.enable|\
        vendor.audio.feature.ras.enable|vendor.audio.feature.snd_mon.enable|\
        vendor.audio.feature.src_trkn.enable|vendor.audio.feature.ssrec.enable|\
        vendor.audio.feature.usb_offload.enable|vendor.audio.feature.usb_offload_burst_mode.enable|\
        vendor.audio.feature.vbat.enable|vendor.audio.feature.kpi_optimize.enable|\
        vendor.audio.feature.fluence.enable|vendor.audio.feature.deepbuffer_as_primary.enable|\
        vendor.audio.feature.dmabuf.cma.memory.enable|vendor.audio.feature.dsm_feedback.enable|\
        vendor.audio.feature.ext_hw_plugin.enable|vendor.audio.feature.external_dsp.enable|\
        vendor.audio.feature.external_speaker.enable|vendor.audio.feature.external_speaker_tfa.enable|\
        vendor.audio.feature.hwdep_cal.enable|vendor.audio.feature.maxx_audio.enable|\
        vendor.audio.feature.record_play_concurency.enable|vendor.audio.feature.usb_offload_sidetone_volume.enable|\
        vendor.audio.feature.wsa.enable|vendor.audio.feature.compr_cap.enable|\
        vendor.audio.feature.compr_voip.enable|vendor.audio.feature.audiozoom.enable|\
        vendor.audio.feature.anc_headset.enable)
            RET_META="none:26:30:qti_ahal" ;;
        vendor.audio.playback.dsp.pathdelay|vendor.audio.tunnel.encode|\
        vendor.audio.usb.disable.sidetone|vendor.audio.offload.passthrough|\
        vendor.audio.offload.track.enable|vendor.audio.hal.output.suspend.supported|\
        vendor.audio.enable.mirrorlink|vendor.audio.hal.boot.timeout.ms|\
        vendor.audio.offload.multiaac.enable|vendor.audio.parser.ip.buffer.size)
            RET_META="none:26:30:qti_ahal" ;;
        persist.vendor.audio.format.24bit|persist.vendor.audio.hifi.int_codec|\
        persist.vendor.audio.fluence.*|persist.vendor.audio.ambisonic.*|\
        persist.vendor.audio.apptype.multirec.enabled|persist.vendor.audio.avs.afe_api_version|\
        persist.vendor.audio.ha_proxy.enabled|persist.vendor.audio.spv3.enable|\
        persist.vendor.audio.voicecall.speaker.stereo)
            RET_META="none:26:30:qti_ahal" ;;
        ro.vendor.audio.sdk.fluencetype|ro.vendor.audio.sdk.ssr)
            RET_META="none:26:30:qti_ahal" ;;
        vendor.audio_hal.in_period_size|vendor.audio_hal.period_multiplier)
            RET_META="none:26:30:qti_ahal" ;;
        vendor.audio.dts.sfx|ro.vendor.audio.dts.sfx)
            RET_META=":26:99:dts" ;;

        # 6. Legacy Bluetooth Stack & QTI Controllers
        ro.bluetooth.library_name)
            RET_META="none:26:30:aosp" ;;
        persist.bluetooth.a2dp.max_bitpool_size)
            RET_META="none:14:23:aosp" ;;
        persist.bluetooth.a2dp.aptx|persist.bluetooth.a2dp.aptx_hd)
            RET_META="none:21:26:aosp" ;;
        persist.vendor.bt.*)
            RET_META="none:26:31:qti" ;;
        persist.vendor.qcom.bluetooth.a2dp_mcast_test.enabled|\
        persist.vendor.qcom.bluetooth.aac_vbr_ctl.enabled|\
        persist.vendor.qcom.bluetooth.twsp_state.enabled)
            RET_META="none:26:31:qti" ;;

        *) RET_META=":::" ;;
    esac
}

get_prop_lifecycle() {
    resolve_prop_lifecycle "$@"
    echo "$RET_META"
}

get_aosp_ref_default() {
    resolve_prop_lifecycle "$1" "$2"
    echo "${RET_META%%:*}"
}
