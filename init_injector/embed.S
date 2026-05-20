.section .rodata
.global embed
embed:
.incbin "libinjectrclib.so"
embed_end:
.global embed_size
embed_size:
.quad embed_end - embed
