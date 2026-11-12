# Generated AWK resolver for aosp_reference
function resolve_meta(p, api) {
    if (p in exact) return exact[p];
    if (p ~ /^.*dolby\.fade_switch.*$/) return "true:28:30:dolby";
    if (p ~ /^.*dolby\.surround\.enable.*$/) return "true:28:30:dolby";
    if (p ~ /^.*dolby\.eq\.half.*$/) return "true:28:30:dolby";
    if (p ~ /^.*dolby\.profile\.default.*$/) return "true:28:30:dolby";
    if (p ~ /^.*dolby\.dax\.support.*$/) return "true:28:30:dolby";
    if (p ~ /^.*dolby\.control\.support.*$/) return "true:28:30:dolby";
    if (p ~ /^.*dolby\.dax\.version.*$/) return "true:28:30:dolby";
    if (p ~ /^.*dolby\.ds2\..*$/) return "false:19:29:dolby";
    if (p ~ /^.*dolby\.ds\.state.*$/) return "false:19:29:dolby";
    if (p ~ /^ro\.hwui\.text_large_cache_.*$/) return "none:14:28:aosp";
    if (p ~ /^ro\.hwui\.text_small_cache_.*$/) return "none:14:28:aosp";
    if (p ~ /^audio\.offload\.pcm\..*$/) return "true:21:30:qti_ahal";
    if (p ~ /^vendor\.audio\.offload\.pcm\..*$/) return "true:26:30:qti_ahal";
    if (p ~ /^persist\.vendor\.audio\.fluence\..*$/) return "none:26:30:qti_ahal";
    if (p ~ /^persist\.vendor\.audio\.ambisonic\..*$/) return "none:26:30:qti_ahal";
    if (p ~ /^persist\.vendor\.bt\..*$/) return "none:26:31:qti";
    return ":::";
}
BEGIN {
    exact["debug.hwui.renderer"] = "skiagl:28:99:aosp";
    exact["debug.hwui.skia_atrace_enabled"] = "false:31:34:aosp";
    exact["debug.sf.hw"] = "0:9:21:aosp";
    exact["debug.sf.latch_unsignaled"] = "1:30:33:aosp";
    exact["persist.audio.dolby.enabled"] = "false:23:28:dolby";
    exact["persist.bluetooth.a2dp.aptx"] = "none:21:26:aosp";
    exact["persist.bluetooth.a2dp.aptx_hd"] = "none:21:26:aosp";
    exact["persist.bluetooth.a2dp.max_bitpool_size"] = "none:14:23:aosp";
    exact["persist.sys.composition.type"] = "c2d:10:14:aosp";
    exact["persist.vendor.audio.apptype.multirec.enabled"] = "none:26:30:qti_ahal";
    exact["persist.vendor.audio.avs.afe_api_version"] = "none:26:30:qti_ahal";
    exact["persist.vendor.audio.format.24bit"] = "none:26:30:qti_ahal";
    exact["persist.vendor.audio.ha_proxy.enabled"] = "none:26:30:qti_ahal";
    exact["persist.vendor.audio.hifi.int_codec"] = "none:26:30:qti_ahal";
    exact["persist.vendor.audio.spv3.enable"] = "none:26:30:qti_ahal";
    exact["persist.vendor.audio.voicecall.speaker.stereo"] = "none:26:30:qti_ahal";
    exact["persist.vendor.qcom.bluetooth.a2dp_mcast_test.enabled"] = "none:26:31:qti";
    exact["persist.vendor.qcom.bluetooth.aac_vbr_ctl.enabled"] = "none:26:31:qti";
    exact["persist.vendor.qcom.bluetooth.twsp_state.enabled"] = "none:26:31:qti";
    exact["resolve_prop_lifecycle("] = ":::";
    exact["ro.bluetooth.library_name"] = "none:26:30:aosp";
    exact["ro.dolby.present"] = "true:21:28:dolby";
    exact["ro.hwui.drop_shadow_cache_size"] = "none:14:28:aosp";
    exact["ro.hwui.gradient_cache_size"] = "none:14:28:aosp";
    exact["ro.hwui.layer_cache_size"] = "none:14:28:aosp";
    exact["ro.hwui.path_cache_size"] = "none:14:28:aosp";
    exact["ro.hwui.r_buffer_cache_size"] = "none:14:28:aosp";
    exact["ro.hwui.texture_cache_flushrate"] = "none:14:28:aosp";
    exact["ro.hwui.texture_cache_size"] = "none:14:28:aosp";
    exact["ro.vendor.audio.dts.sfx"] = ":26:99:dts";
    exact["ro.vendor.audio.sdk.fluencetype"] = "none:26:30:qti_ahal";
    exact["ro.vendor.audio.sdk.ssr"] = "none:26:30:qti_ahal";
    exact["vendor.audio.dts.sfx"] = ":26:99:dts";
    exact["vendor.audio.enable.mirrorlink"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.a2dp_offload.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.afe_proxy.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.anc_headset.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.audiozoom.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.battery_listener.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.compr_cap.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.compr_voip.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.compress_in.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.compress_meta_data.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.concurrent_capture.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.custom_stereo.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.deepbuffer_as_primary.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.display_port.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.dmabuf.cma.memory.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.dsm_feedback.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.dynamic_ecns.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.ext_hw_plugin.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.external_dsp.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.external_speaker.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.external_speaker_tfa.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.extn_flac_decoder.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.extn_formats.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.extn_resampler.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.fluence.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.fm.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.handset.profile.disable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.hdmi_edid.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.hdmi_passthrough.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.hfp.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.hifi_audio.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.hwdep_cal.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.incall_music.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.keep_alive.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.kpi_optimize.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.maxx_audio.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.multi_voice_session.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.ras.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.record_play_concurency.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.snd_mon.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.spkr_prot.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.src_trkn.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.ssrec.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.usb_offload.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.usb_offload_burst_mode.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.usb_offload_sidetone_volume.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.vbat.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.feature.wsa.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.hal.boot.timeout.ms"] = "none:26:30:qti_ahal";
    exact["vendor.audio.hal.output.suspend.supported"] = "none:26:30:qti_ahal";
    exact["vendor.audio.offload.gapless.enabled"] = "none:19:28:aosp";
    exact["vendor.audio.offload.multiaac.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.offload.multiple.enabled"] = "none:19:28:aosp";
    exact["vendor.audio.offload.passthrough"] = "none:26:30:qti_ahal";
    exact["vendor.audio.offload.track.enable"] = "none:26:30:qti_ahal";
    exact["vendor.audio.parser.ip.buffer.size"] = "none:26:30:qti_ahal";
    exact["vendor.audio.playback.dsp.pathdelay"] = "none:26:30:qti_ahal";
    exact["vendor.audio.tunnel.encode"] = "none:26:30:qti_ahal";
    exact["vendor.audio.usb.disable.sidetone"] = "none:26:30:qti_ahal";
    exact["vendor.audio_hal.in_period_size"] = "none:26:30:qti_ahal";
    exact["vendor.audio_hal.period_multiplier"] = "none:26:30:qti_ahal";
    exact["vendor.display.disable_offline_rotator"] = "1:26:29:qti";
    exact["vendor.display.disable_spec_fence"] = "none:30:31:qti";
    exact["vendor.display.enable_async_powermode"] = "0:28:33:qti";
    exact["vendor.display.enable_rc_support"] = "1:28:31:qti_rc";
    exact["vendor.display.lcd_density"] = "480:21:29:qti";
}
{
    if ($0 != "") {
        m = resolve_meta($0, api);
        print $0 ":" m;
        seen[$0] = 1;
    }
}
END {
    for (p in exact) {
        if (!seen[p]) {
            m = resolve_meta(p, api);
            print p ":" m;
        }
    }
}
