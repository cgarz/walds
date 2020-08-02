walds - Worms Armageddon Language file Desnowflaker

An over-engineered tool to correct silly political correctness pandering changes made to the Steam / GoG language files of Worms Armageddon.

It will alter each language file in a Worms Armageddon/DATA/User/Languages subfolder by replacing all steam specific strings with cd version strings.
For example, in English.txt the following will be changed:
TT_TEAMLIST_TRAINING_5_STEAM  "Best Time" -> TT_TEAMLIST_TRAINING_5_STEAM  "Euthanasia Best Time"
TRAINING_COMBO_ENTRIES_5_STEAM "Advanced Weapon Training" -> TRAINING_COMBO_ENTRIES_5_STEAM "Euthanasia"

It should run with only python. However if pefile is installed it will use that to get the WA.exe version.
Tested on Linux and Wine.
