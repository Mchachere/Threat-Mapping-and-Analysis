# Threat-Mapping-and-Analysis
Python script to extract IP, URL, Domains, and Files from PCAP.  Get SHA256 Hashes from the Files. Run that information against Virus Total, OTX, and Spamhaus and map IP addresses in a KML file to display on Google Earth.

I threw this script together with inspiration from Iktps' file extraction script while also getting the idea about IP mapping from Vinsloev Academies Youtube page on "Network Tracking using Wireshark and Google Maps."
I will update and continue to work on the script as I can.
The PCAPs I work with are from https://www.malware-traffic-analysis.net/training-exercises.html.
Note: The current iteration of the Script does not store the Extracted files from the payload onto your computer; it saves them in a temporary space to compute them into hashes only.
Future iterations will include downloading files from URLs for hash computing; caution is advised.
