# mitmproxy2case 


A command-line tool to convert mitmproxy recordings to httprunner testcases

`mitmproxy2case` 是一款将使用mitmproxy抓包的数据流转换为httprunner执行测试用例的命令行脚本工具


### 使用方式
First record requests and responses using mitmproxy. For instance:

```
mitmdump --save-stream-file recording &

```
If you need to filter the request URI, including allow the pattern url path or ignore the images、js and so on ,you can add the filter.yaml ,such as:
```
# example:
allow:
  path:
    - '/public-vue/common/index.html'
    - '/zbankws/ws/account/v1/accountStatus'
    - '/log-collect/front-behaviour'

ignore:
  - image: '*.gif/*.jpg/*.png/*.svg/*.img/*.ico'
  - js: '*.js'
  - css: '*.css/*.scss'
  - other: '*.ttf/*.otf'

```

Then use mitmproxy2case to convert the recording to JSON:
```
mitmproxy2case  recording --filter filter.yaml 
```

Finally, you will get the Cases.json File, you can use the file coordinate with the httprunner to test HTTP Interfaces;
```
hrun Cases.json
```

### Installation

```
$ pip install mitmproxy2case
```


### License

[MIT](https://github.com/T8840/mitmproxy2case/blob/master/LICENSE)

