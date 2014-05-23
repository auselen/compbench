#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

struct engine {
    void *(*init)(void);
    void (*destroy)(void *engine);
    int (*inflate)(const unsigned char *src, const unsigned char *dst,
                   size_t *size, void *engine);
    int (*deflate)(unsigned char *dst, unsigned char *src, size_t n);
    const char *name;
};

static struct engine *engines[] = {
    {NULL, NULL, NULL, NULL, "LZO"},
};

static ssize_t avail_show(struct kobject *kobj, struct kobj_attribute *attr,
                          char *buf)
{
    int i = 0;
#ifdef CONFIG_LZO_COMPRESS
    i += sprintf(buf + i, "LZO_COMPRESS");
#endif
#ifdef CONFIG_LZ4_COMPRESS
    if (i > 0)
        i += sprintf(buf + i, ", ");
    i += sprintf(buf + i, "LZ4_COMPRESS");
#endif
    i += sprintf(buf + i, "\n");

    return i;
}

static struct kobj_attribute avail_attribute =
    __ATTR_RO(avail);

static struct attribute *attrs[] = {
    &avail_attribute.attr,
    NULL,
};

static struct attribute_group attr_group = {
    .attrs = attrs,
};

static struct kobject *cb_kobj;

static int __init compbench_init(void)
{
    int retval;

    cb_kobj = kobject_create_and_add("compbench", kernel_kobj);
    if (!cb_kobj)
        return -ENOMEM;

    retval = sysfs_create_group(cb_kobj, &attr_group);
    if (retval)
        kobject_put(cb_kobj);

    return retval;
}

static void __exit compbench_cleanup(void)
{
    kobject_put(cb_kobj);
}

module_init(compbench_init);
module_exit(compbench_cleanup);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ali Utku Selen");
MODULE_DESCRIPTION("Compression module benchmarker");
