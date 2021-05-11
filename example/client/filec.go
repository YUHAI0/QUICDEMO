package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
)

func main() {
	verbose := flag.Bool("v", false, "verbose")
	//quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	sendFile := flag.String("sfile", "", "file to send")
	flag.Parse()
	urls := flag.Args()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	//pool, err := x509.SystemCertPool()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//testdata.AddRootCA(pool)

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	//testdata.AddRootCA(pool)
	caCertPath := "/Users/yuhai/Projects/quic-go/example/ca.crt"

	caCrt, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		fmt.Println("ReadFile err:", err)
		return
	}
	pool.AppendCertsFromPEM(caCrt)

	var qconf quic.Config
	if *enableQlog {
		qconf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("client_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &qconf,
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		logger.Infof("GET %s", addr)
		go func(addr string) {
			//rsp, err := hclient.Get(addr)
			//addTemplateWeb(hclient, addr, *sendFile)

			//prepare the reader instances to encode
			values := map[string]io.Reader{
				"file":  mustOpen(*sendFile), // lets assume its this file
				//"other": strings.NewReader("hello world!"),
			}
			uerr := Upload(hclient, addr, values)
			if uerr != nil {
				print("upload:", uerr.Error())
				return
			}
			//if err != nil {
			//	log.Fatal("get err: ", err)
			//}
			//logger.Infof("Got response for %s: %#v", addr, rsp)

			//body := &bytes.Buffer{}
			//_, err = io.Copy(body, rsp.Body)
			//if err != nil {
			//	log.Fatal(err)
			//}
			//if *quiet {
			//	logger.Infof("Request Body: %d bytes", body.Len())
			//} else {
			//	logger.Infof("Request Body:")
			//	logger.Infof("%s", body.Bytes())
			//}
			wg.Done()
		}(addr)
	}
	wg.Wait()
}

func addTemplateWeb(client *http.Client, addr string, path string) {
	// 创建表单文件
	// CreateFormFile 用来创建表单，第一个参数是字段名，第二个参数是文件名
	//var feat addfeature
	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)
	//writer.WriteField("sublib", "1")
	formFile, err := writer.CreateFormFile("file", "data")
	if err != nil {
		fmt.Println("Create form file failed: %s\n", err)
	}

	// 从文件读取数据，写入表单
	srcFile, err := os.Open(path)
	if err != nil {
		fmt.Println("%Open source file failed: s\n", err)
	}
	defer srcFile.Close()
	_, err = io.Copy(formFile, srcFile)
	if err != nil {
		fmt.Println("Write to form file falied: %s\n", err)
	}

	// 发送表单
	contentType := writer.FormDataContentType()
	writer.Close() // 发送之前必须调用Close()以写入结尾行

	re, err := client.Post(addr, contentType, buf)

	fmt.Println("Buf size: ", buf.Len())
	fmt.Println("Post: ", re)
	return
}


func Upload(client *http.Client, url string, values map[string]io.Reader) (err error) {
	// Prepare a form that you will submit to that URL.
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for key, r := range values {
		var fw io.Writer
		if x, ok := r.(io.Closer); ok {
			defer x.Close()
		}
		// Add an image file
		if x, ok := r.(*os.File); ok {
			if fw, err = w.CreateFormFile(key, x.Name()); err != nil {
				return
			}
		} else {
			// Add other fields
			if fw, err = w.CreateFormField(key); err != nil {
				return
			}
		}
		if _, err = io.Copy(fw, r); err != nil {
			return err
		}

	}
	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("POST", url, &b)
	if err != nil {
		return
	}
	// Don't forget to set the content type, this will contain the boundary.
	req.Header.Set("Content-Type", w.FormDataContentType())

	// Submit the request
	res, err := client.Do(req)
	if err != nil {
		return
	}
	print("Upload response: ", res)

	// Check the response
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
	}
	return
}

func mustOpen(f string) *os.File {
	//f = "/Users/yuhai/Projects/portkey/100mr"
	r, err := os.Open(f)
	if err != nil {
		panic(err)
	}
	return r
}