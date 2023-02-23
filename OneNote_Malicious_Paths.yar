rule OneNote_Malicious_Paths
{
	meta:
        author = "Nicholas Dhaeyer - @DhaeyerWolf"
        date_created = "2023-02-23"
        date_last_modified = "2023-02-23"
        description = "Looks for OneNote Files with known malicious strings"
		
    strings:
		$start = { e4 52 5c 7b 8c d8 a7 4d ae b1 53 78 d0 29 96 d3 } //beginning of a OneNote file
		
		//Start of malicious strings
		$hex_string1 = { 5a 00 3a 00 5c 00 62 00 75 00 69 00 6c 00 64 00 65 00 72 00 5c } // Z:\builder\
		$hex_string2 = { 5a 00 3a 00 5c 00 62 00 75 00 69 00 6c 00 64 00 5c } // Z:\build\
		
    condition:
        $start at 0 and ($hex_string1 or $hex_string2)
}
