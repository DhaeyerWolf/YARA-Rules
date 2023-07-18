rule Embedded_RTF_File
{
    meta:
        author = "Nicholas Dhaeyer - @DhaeyerWolf"
        date_created = "2023-07-18"
        date_last_modified = "2023-07-18"
        description = "Related to CVE-2023-36884. Hunts for any zip-like archive (eg. office documents) that have an embedded .rtf file, based on the '.rtf' extension of the file."
		yarahub_uuid = "800682b8-e810-49d2-91b3-dfaafb61637f"
		date = "2023-07-18"
		yarahub_license = "CC BY-SA 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "b6ad6198e155921dc11c855c03d8c264"

    strings:
		$start = { 50 4B 03 04 } //beginning of a archive file
	
        $rtf =  { 2E 72 74 66 } //.rtf

    condition:
        $start at 0 and (#rtf > 1) // make sure that the ".rtf" string is observed more than once to avoid false positives.
}