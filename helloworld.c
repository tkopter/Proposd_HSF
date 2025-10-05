// helloworld.c — NO-DFX: gizli.c'yi doğrudan çağırır (BRAM/DFX yok)
// NOT: gizli.c aynen kalır; ölçüm pencereleri gizli.c içindedir.

#include "xparameters.h"
#include "xil_printf.h"
#include <stdint.h>

extern void gizli_fonksiyon(uint32_t mailbox_addr);  // gizli.c'deki BRAM entry (değiştirilmedi)

int main(void)
{
    xil_printf("\n[NO-DFX] start\n");

    // BRAM mailbox yerine normal bir 32-bit değişken veriyoruz.
    static volatile uint32_t mailbox = 0;

    // Orijinal tasarımda dış döngü varken (hop), burada sadece çağırıyoruz.
    // gizli.c ilk çağrıda menüyü gösterir, seçim alınca bir tur çalışır ve döner.
    while (1) {
        gizli_fonksiyon((uint32_t)(uintptr_t)&mailbox);

        // Orijinal koddaki [RET] çıktısının sade eşleniği:
        xil_printf("[RET ] mailbox@0x%08X val=0x%08X\r\n",
                   (unsigned)(uintptr_t)&mailbox, (unsigned)mailbox);
    }
}
