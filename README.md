
pack
```

  paktool.exe pack {OPTIONS}

    create PAK

  OPTIONS:

      -s[path...], --src=[path...]      The source directory
      -c[ext...],
      --compress_file_ext=[ext...]      The file types that need to be
                                        compressed
      -i[uint32], --isecret=[uint32]    The index secret
      -d[uint32], --dsecret=[uint32]    The data secret
      --keep_parent_directory=[0/1]     The data secret
      -o[file path]                     The output file path
      --maximum=[MB]                    The maximum size of a single file

```

unpack
```

  paktool.exe unpack {OPTIONS}

    unpack PAK file

  OPTIONS:

      -i[file path]                     The .PACK file path
      -o[file path]                     The output directory

```
