walds - Worms Armageddon Language files DeSnowflaker

An over-engineered tool to correct silly political correctness pandering changes made to the Steam / GoG language files of Worms Armageddon.

When run, the W:A installation folder is detected or prompted for. Then each language file in the current versions language subfolder will have all Steam specific strings replaced with CD version strings.

For example, in English.txt the following will be changed:  
`TT_TEAMLIST_TRAINING_5_STEAM "Best Time"` -> `TT_TEAMLIST_TRAINING_5_STEAM "Euthanasia Best Time"`  
`TRAINING_COMBO_ENTRIES_5_STEAM "Advanced Weapon Training"` -> `TRAINING_COMBO_ENTRIES_5_STEAM "Euthanasia"`  

It should run with python and the built in modules alone. However if pefile is installed it will use that to get the WA.exe version.
Tested on Linux and Wine.
