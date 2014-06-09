
__attribute__((constructor)) int eld_init();
__attribute__((destructor)) int eld_finish();
void *dlsym(void *handle, char *symbol);
void *dlopen(char *filename, int flag);
int dlclose(void *handle);
