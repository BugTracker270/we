#include <assert.h>

#include "ps4.h"
#include "defines.h"

#define KERNEL_CHUNK_SIZE 0x1000
#define KERNEL_CHUNK_NUMBER 0x69B8

void decrypt_pups(const char * InputPath, const char * OutputPath);
uint8_t GetElapsed(uint64_t ResetInterval);

int sock;

time_t prevtime;



uint8_t GetElapsed(uint64_t ResetInterval) {

 time_t currenttime = time(0);
 uint64_t elapsed = currenttime - prevtime;

 if ((ResetInterval == 0) || (elapsed >= ResetInterval)) {
    prevtime = currenttime;
    return 1;
 }

 return 0;
}



int _main(struct thread* td) {
  initKernel();
  initLibc();
  initPthread();
  initNetwork();
  initSysUtil();

  char fwstr[16];
  fwstr[0] = 0;
  if (get_firmware_string(fwstr) != 0) {
    strcpy(fwstr, "unknown");
  }

  char msg[160];

  /*
   * Announce BEFORE anything else. In the original build the first
   * printf_notification() came after jailbreak(), so a failure there was
   * an invisible hang. Now every failure mode prints something.
   */
  snprintf(msg, sizeof(msg), "PUP Decrypter: start (fw=%s)", fwstr);
  printf_notification(msg);

  /*
   * Report privilege state. This build deliberately contains NO jailbreak()
   * / kexec() call: the previous freeze was caused by kexec running a kernel
   * payload whose firmware offsets this binary does not contain (built
   * 2024-04-07, before 13.52 existed).
   */
  snprintf(msg, sizeof(msg), "uid=%d sandbox=%d jb=%d", getuid(), is_in_sandbox(), is_jailbroken());
  printf_notification(msg);

  /*
   * Probe the kernel encrypt-service device before touching any PUP data.
   * Opening is harmless; it only tells us whether we hold enough privilege.
   */
  int fd = open("/dev/pup_update0", O_RDWR, 0);
  int oerr = errno;
  if (fd >= 0) {
    close(fd);
  }
  snprintf(msg, sizeof(msg), "pup_update0 fd=%d errno=%d", fd, oerr);
  printf_notification(msg);

  if (fd < 0) {
    printf_notification("ABORT: pup_update0 not accessible");
    return 0;
  }

  printf_notification("Running PS4 PUP Decrypter");

  decrypt_pups("/mnt/usb0/safe.PS4UPDATE.PUP", "/mnt/usb0/%s.dec");

  printf_notification("Finished PS4 PUP Decrypter");

  return 0;
}
