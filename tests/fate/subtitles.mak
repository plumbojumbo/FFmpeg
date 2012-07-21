FATE_SUBTITLES += fate-sub-jacosub
fate-sub-jacosub: CMD = md5 -i $(SAMPLES)/sub/JACOsub_capability_tester.jss -f ass

FATE_SUBTITLES += fate-sub-microdvd
fate-sub-microdvd: CMD = md5 -i $(SAMPLES)/sub/MicroDVD_capability_tester.sub -f ass

FATE_SUBTITLES += fate-sub-movtext
fate-sub-movtext: CMD = md5 -i $(SAMPLES)/sub/MovText_capability_tester.mp4 -f ass

FATE_SUBTITLES += fate-sub-realtext
fate-sub-realtext: CMD = md5 -i $(SAMPLES)/sub/RealText_capability_tester.rt -f ass

FATE_SUBTITLES += fate-sub-sami
fate-sub-sami: CMD = md5 -i $(SAMPLES)/sub/SAMI_capability_tester.smi -f ass

FATE_SUBTITLES += fate-sub-srt
fate-sub-srt: CMD = md5 -i $(SAMPLES)/sub/SubRip_capability_tester.srt -f ass

FATE_SAMPLES_FFMPEG += $(FATE_SUBTITLES)
fate-subtitles: $(FATE_SUBTITLES)
