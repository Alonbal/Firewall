#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alon Balassiano");

struct class* fw_sysfs_class = NULL;


static int __init module_init_function(void) 
{
    //create a shared class
    fw_sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(fw_sysfs_class)) return -1;
    
    //initialize hook and inspection logic in inspection.c
    if (init_inspection())
    {
        class_destroy(fw_sysfs_class);
        return -1;
    }

    //initialize rule logic in rule.c
    if (init_rule_table()) 
    {
        release_inspection();
        class_destroy(fw_sysfs_class);
        return -1;
    }
    
    //initialize log providing logic in log.c
    if (init_log_module())
    {
        release_rule_table();
        release_inspection();
        class_destroy(fw_sysfs_class);
        return -1;
    }
    return 0;
}


static void __exit module_exit_function(void) 
{	
    release_log_module();
    release_rule_table();
    release_inspection();
	class_destroy(fw_sysfs_class);
}


module_init(module_init_function);
module_exit(module_exit_function);

