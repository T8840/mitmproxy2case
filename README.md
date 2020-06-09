# mitmproxy2case


A command-line tool to convert mitmproxy recordings to httprunner testcases

`mitmproxy2case` 是一款将使用mitmproxy抓包的数据流转换为httprunner执行测试用例的命令行脚本工具


### Usage
First record requests and responses using mitmproxy. For instance:

```
mitmdump --save-stream-file recording &

```
Then use mitmproxy2case to convert the recording to JSON:
```
mitmproxy2case --record recording --filter filter.yaml 
```

### Installation

```
$ pip install mitmproxy2case
```


### License
[MIT](https://github.com/T8840/mitmproxy2case/blob/master/LICENSE)


