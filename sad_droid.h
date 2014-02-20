#ifndef SAD_DROID_H
#define SAD_DROID_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/time.h>
#else
#include <sys/ioctl.h>
#include <sys/mman.h>
#endif


/*FIXME: dude, srsly, look up the proper defines*/
/* max assumed length of SELinux context */
#define CONT_MAXLEN 		256
/* max assumed len of binary to execute */
#define NAMELEN 		256

/*FIXME: Check ioctl number */
#define SAD_DROID_IOCTL_MAGIC 	0x8e

/* device name, used in /dev and /sys */
#define SAD_DROID_DEVICE_NAME 	"sad_droid"

/*! \struct sad_droid_trans
  \brief information about context transition point
  */
struct sad_droid_trans {
	unsigned long addr; 		/*!< address of the break */
	char new_cont[CONT_MAXLEN]; 	/*!< new context */
	char bin_file[NAMELEN];		/*!< binary which process to probe */
};
	
/*! \def sad_droid_IOCTL_SET_BREAK
  \brief set a new context transition control point
  */
#define SAD_DROID_IOCTL_SET_BREAK \
	_IOWR(SAD_DROID_IOCTL_MAGIC, 0, struct sad_droid_trans)

/*! \def SAD_DROID_IOCTL_DEL_BREAK \
  \brief delete context transition control point
  */
#define SAD_DROID_IOCTL_DEL_BREAK \
	_IOWR(SAD_DROID_IOCTL_MAGIC, 1, struct sad_droid_trans)

#endif /* SAD_DROID_H */
