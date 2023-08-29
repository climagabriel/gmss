#include <stdio.h>
#include <maxminddb.h>

int main() {

	MMDB_s mmdb;
	int status = MMDB_open("GeoIP2-ISP.mmdb", MMDB_MODE_MMAP, &mmdb);
	if (status != MMDB_SUCCESS) {
		printf("oh no\n");
		return 1;
	} else {
		printf("ye boiiii\n");
	}

	int gai_error, mmdb_error;
	MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "92.223.113.197", &gai_error, &mmdb_error);
	if (gai_error != 0) printf("getaddr error\n");
	if (MMDB_SUCCESS != mmdb_error) printf("mmdb error\n");

	MMDB_entry_data_list_s *entry_data_list = NULL;
	if (!result.found_entry) { printf("no entry\n"); } else
	{
		if (result.found_entry) {
			int status = MMDB_get_entry_data_list(&result.entry, &entry_data_list);
			if (status != MMDB_SUCCESS) {
				printf("oh no\n");
				return 1;
			} else {
				printf("ye boiiii\n");
			}
		}
	MMDB_dump_entry_data_list(stdout, entry_data_list, 2);
	MMDB_free_entry_data_list(entry_data_list);
	}

	MMDB_entry_data_s entry_data;
	MMDB_get_value(&result.entry, &entry_data, "isp", NULL);
	printf("%.*s\n", (int)entry_data.data_size, entry_data.utf8_string);
	MMDB_close(&mmdb);
	printf("closed db\n");
}
