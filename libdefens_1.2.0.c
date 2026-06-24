#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <stdint.h>
#include <unistd.h>
#include <link.h> 
#include <string.h>

// --- ЦВЕТА ---
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_RESET   "\033[0m"

typedef int (*orig_system_type)(const char *command);
orig_system_type real_system = NULL;


uintptr_t main_text_start = 0;
uintptr_t main_text_end = 0;


int header_handler(struct dl_phdr_info *info, size_t size, void *data) {
    
    if (info->dlpi_name && info->dlpi_name[0] != '\0') {
        return 0; 
    }

    
    for (int i = 0; i < info->dlpi_phnum; i++) {

        if (info->dlpi_phdr[i].p_type == PT_LOAD && (info->dlpi_phdr[i].p_flags & PF_X)) {

            main_text_start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
            main_text_end = main_text_start + info->dlpi_phdr[i].p_memsz;
            
            printf(COLOR_BLUE "[RASP INIT] Обнаружен сегмент кода (.text):\n");
            printf("            Start: 0x%lx | End: 0x%lx\n" COLOR_RESET, main_text_start, main_text_end);
            return 1; 
        }
    }
    return 0;
}

void __attribute__((constructor)) init_defense() {
    real_system = (orig_system_type)dlsym(RTLD_NEXT, "system");
    if (!real_system) exit(1);

    dl_iterate_phdr(header_handler, NULL);
    
    if (main_text_start == 0) {
        printf(COLOR_RED "[RASP ERROR] Не удалось определить границы кода!\n" COLOR_RESET);
    }
}


int is_user_code(void *addr) {
    uintptr_t a = (uintptr_t)addr;
    if (a >= main_text_start && a < main_text_end) {
        return 1; 
    }
    return 0; 
}

int smart_check() {
    void *buffer[20];
    int nptrs = backtrace(buffer, 20);
    
    printf(COLOR_YELLOW "[RASP DEBUG] Анализ стека (поиск User Code)...\n" COLOR_RESET);

    int found_user_code = 0;

    for (int i = 0; i < nptrs; i++) {
        void *ret_addr = buffer[i];
        
       
        if (is_user_code(ret_addr)) {
            found_user_code = 1;
            printf("   [%d] %p -> USER CODE FOUND!\n", i, ret_addr);
            
            unsigned char *code_ptr = (unsigned char *)ret_addr;
            
            
            if (*(code_ptr - 5) == 0xE8) {
                printf(COLOR_GREEN "       [OK] Инструкция CALL подтверждена.\n" COLOR_RESET);
                return 0; 
            } else {
                 printf(COLOR_RED "       [FAIL] Инструкции CALL нет! (Байт: 0x%02x)\n" COLOR_RESET, *(code_ptr - 5));
                 return 1; 
            }
        } else {
            // библиотека (ld-linux, libc ...) 
            // printf("   [%d] %p -> System/Library\n", i, ret_addr);
        }
    }

    if (!found_user_code) {
        //potom
    }

    return 0;
}

int system(const char *command) {
    if (smart_check()) {
        printf("\n" COLOR_RED "[RASP ALERT] ROP-АТАКА ЗАБЛОКИРОВАНА!\n");
        printf("Причина: Вызов system() инициирован из User-кода без инструкции CALL.\n" COLOR_RESET);
        exit(1337);
    }

    printf(COLOR_GREEN "[RASP AUDIT] Разрешено.\n" COLOR_RESET);
    return real_system(command);
}
