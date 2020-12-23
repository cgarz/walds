## walds - Worms Armageddon Language files DeSnowflaker

An over-engineered tool to correct silly political correctness pandering changes made to the Steam / GoG language files of Worms Armageddon.

When run, the W:A installation folder is detected or prompted for. Then each language file in the current versions language subfolder will have all Steam specific strings replaced with CD version strings.

For example, in English.txt the following will be changed:  
`TT_TEAMLIST_TRAINING_5_STEAM "Best Time"` -> `TT_TEAMLIST_TRAINING_5_STEAM "Euthanasia Best Time"`  
`TRAINING_COMBO_ENTRIES_5_STEAM "Advanced Weapon Training"` -> `TRAINING_COMBO_ENTRIES_5_STEAM "Euthanasia"`  

It should run with python and the built in modules alone. However if pefile is installed it will use that to get the WA.exe version.
Tested on Linux and Wine.

This pairs well with the [Missing Content zip file](https://drive.google.com/uc?authuser=0&id=0B6A_ITzSjsF3ZDRTN2ZKUUdzdDA) from here:
https://steamcommunity.com/sharedfiles/filedetails/?id=156231406

Changes in the steam/GoG version are listed here:
https://worms2d.info/Steam_release_(Worms_Armageddon)
