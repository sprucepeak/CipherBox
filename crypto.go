package main

/*
CipherBox — 基于 mygo Native UI 的现代轻量级文件加密工具
核心架构与算法：
- XChaCha20-Poly1305 认证加密（AEAD）
- Argon2id 密码学密钥派生（支持高强度偏执模式）
- Reed-Solomon 矩阵纠错编码（自定位分块校验与静默数据自动修复）
- 多密钥文件混合派生、合理可否认性（隐匿加密卷）
- 智能分块拆分/重组、Deflate 压缩打包与安全原子替换
*/

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/reedsolomon"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// 判断路径是否为支持的加密卷格式（优先匹配 .sbx，向前兼容 .pcv）
func isVolumeExt(path string) bool {
	return strings.HasSuffix(path, VolumeExt) || strings.HasSuffix(path, ".pcv")
}

// 检查是否为加密分卷（如 .sbx.0 或 .pcv.0）
func isSplitVolume(path string) (bool, string) {
	ext := filepath.Ext(path)
	if len(ext) > 1 && ext[1] >= '0' && ext[1] <= '9' {
		if strings.Contains(path, VolumeExt+".") {
			return true, VolumeExt
		}
		if strings.Contains(path, ".pcv.") {
			return true, ".pcv"
		}
	}
	return false, ""
}

// 去除加密卷扩展名（支持 .sbx 和 .pcv）
func trimVolumeExt(path string) string {
	if strings.HasSuffix(path, VolumeExt) {
		return strings.TrimSuffix(path, VolumeExt)
	}
	return strings.TrimSuffix(path, ".pcv")
}

// GUI hooks（由 ui.go 注入）
var invalidate func() = func() {}

func update() {
	if invalidate != nil {
		invalidate()
	}
}

// check 在 err 非空时 panic，收敛重复的 `if err != nil { panic(err) }`
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// must 返回 v，并在 err 非空时 panic（用于需要丢弃首返回值的调用）
func must[T any](v T, err error) T {
	check(err)
	return v
}

// fail 设置红色错误状态并刷新界面
func fail(msg string) {
	mainStatus = msg
	mainStatusColor = RED
	update()
}

type compressorProgress struct {
	io.Reader
}

func (p *compressorProgress) Read(data []byte) (int, error) {
	if !working {
		return 0, io.EOF
	}
	read, err := p.Reader.Read(data)
	compressDone += int64(read)
	progress, speed, eta = statify(compressDone, compressTotal, compressStart)
	if compress {
		popupStatus = fmt.Sprintf("正在压缩，速度 %.2f MiB/s（预计剩余 %s）", speed, eta)
	} else {
		popupStatus = fmt.Sprintf("正在合并，速度 %.2f MiB/s（预计剩余 %s）", speed, eta)
	}
	update()
	return read, err
}

type encryptedZipWriter struct {
	_w      io.Writer
	_stream cipher.Stream
}

func (ezw *encryptedZipWriter) Write(data []byte) (n int, err error) {
	dst := make([]byte, len(data))
	ezw._stream.XORKeyStream(dst, data)
	return ezw._w.Write(dst)
}

type encryptedZipReader struct {
	_r      io.Reader
	_stream cipher.Stream
}

func (ezr *encryptedZipReader) Read(data []byte) (n int, err error) {
	src := make([]byte, len(data))
	n, err = ezr._r.Read(src)
	if err == nil && n > 0 {
		dst := make([]byte, n)
		ezr._stream.XORKeyStream(dst, src[:n])
		if copy(data, dst) != n {
			panic(errors.New("内置 copy() 函数失败"))
		}
	}
	return n, err
}

func onClickStartButton() {
	// Start button should be disabled if these conditions are true; don't do anything if so
	if (len(keyfiles) == 0 && password == "") || (mode == "encrypt" && password != cpassword) {
		return
	}

	if keyfile && keyfiles == nil {
		fail("请选择你的密钥文件")
		return
	}
	tmp, err := strconv.Atoi(splitSize)
	if split && (splitSize == "" || err != nil || tmp <= 0) {
		fail("分块大小无效")
		return
	}

	// Check if output file already exists
	_, err = os.Stat(outputFile)

	// Check if any split chunks already exist
	if split {
		names, err2 := filepath.Glob(outputFile + ".*")
		check(err2)
		if len(names) > 0 {
			err = nil
		} else {
			err = os.ErrNotExist
		}
	}

	// If output file already exists, show the overwrite modal
	// When confirmed: decryption verifies password to .incomplete first and only replaces on full success.
	if err == nil && !recursively {
		showOverwrite = true
		update()
	} else { // Nothing to worry about, start working
		showProgress = true
		canCancel = true
		update()
		if !recursively {
			go func() {
				work()
				working = false
				showProgress = false
				update()
			}()
		} else {
			// Store variables as they will be cleared
			oldPassword := password
			oldKeyfile := keyfile
			oldKeyfiles := keyfiles
			oldKeyfileOrdered := keyfileOrdered
			oldKeyfileLabel := keyfileLabel
			oldComments := comments
			oldParanoid := paranoid
			oldReedsolo := reedsolo
			oldDeniability := deniability
			oldSplit := split
			oldSplitSize := splitSize
			oldSplitSelected := splitSelected
			oldDelete := delete_
			files := allFiles
			go func() {
				for _, file := range files {
					// Simulate dropping the file
					onDrop([]string{file})

					// Restore variables and options
					password = oldPassword
					cpassword = oldPassword
					keyfile = oldKeyfile
					keyfiles = oldKeyfiles
					keyfileOrdered = oldKeyfileOrdered
					keyfileLabel = oldKeyfileLabel
					comments = oldComments
					paranoid = oldParanoid
					reedsolo = oldReedsolo
					if mode != "decrypt" {
						deniability = oldDeniability
					}
					split = oldSplit
					splitSize = oldSplitSize
					splitSelected = oldSplitSelected
					delete_ = oldDelete

					work()
					if !working {
						resetUI()
						cancel(nil, nil)
						showProgress = false
						update()
						return
					}
				}
				working = false
				showProgress = false
				update()
			}()
		}
	}
}

func formatItemCount(files, folders int) string {
	if folders == 0 {
		return fmt.Sprintf("%d 个文件", files)
	}
	if files == 0 {
		return fmt.Sprintf("%d 个文件夹", folders)
	}
	return fmt.Sprintf("%d 个文件和 %d 个文件夹", files, folders)
}

func onDrop(names []string) {
	if showKeyfile {
		seen := make(map[string]bool)
		for _, k := range keyfiles {
			seen[k] = true
		}
		for _, name := range names {
			if seen[name] {
				continue
			}
			stat, err := os.Stat(name)
			if err != nil || stat.IsDir() {
				continue
			}
			fin, err := os.Open(name)
			if err != nil {
				showKeyfile = false
				resetUI()
				accessDenied("密钥文件已读取")
				update()
				return
			}
			fin.Close()
			seen[name] = true
			keyfiles = append(keyfiles, name)
		}
		if len(keyfiles) == 0 {
			keyfileLabel = "未选择"
		} else if len(keyfiles) == 1 {
			keyfileLabel = "使用 1 个密钥文件"
		} else {
			keyfileLabel = fmt.Sprintf("使用 %d 个密钥文件", len(keyfiles))
		}
		update()
		return
	}

	scanning = true
	files, folders := 0, 0
	compressDone, compressTotal = 0, 0
	resetUI()

	// One item dropped
	if len(names) == 1 {
		stat, err := os.Stat(names[0])
		if err != nil {
			fail("无法获取拖入项信息")
			return
		}

		if stat.IsDir() {
			folders++
			mode = "encrypt"
			inputLabel = "1 个文件夹"
			startLabel = "压缩并加密"
			onlyFolders = append(onlyFolders, names[0])
			inputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
			outputFile = inputFile + VolumeExt
		} else {
			files++
			requiredFreeSpace = stat.Size()

			// Is the file a part of a split volume?
			isSplit, splitExt := isSplitVolume(names[0])

			if isVolumeExt(names[0]) || isSplit {
				mode = "decrypt"
				inputLabel = "待解密的卷"
				startLabel = "解密"
				commentsLabel = "备注（只读）："
				commentsDisabled = true

				if isSplit {
					ind := strings.Index(names[0], splitExt)
					inputFile = names[0][:ind+len(splitExt)]
					outputFile = names[0][:ind]
					recombine = true

					for totalFiles := 0; ; totalFiles++ {
						st, err := os.Stat(fmt.Sprintf("%s.%d", inputFile, totalFiles))
						if err != nil {
							break
						}
						compressTotal += st.Size()
					}
					requiredFreeSpace = compressTotal
				} else {
					outputFile = trimVolumeExt(names[0])
				}

				openPath := names[0]
				if isSplit {
					openPath += ".0"
				}
				fin, err := os.Open(openPath)
				if err != nil {
					resetUI()
					accessDenied("Read")
					update()
					return
				}

				magic := make([]byte, 4)
				if _, err := io.ReadFull(fin, magic); err != nil {
					fin.Close()
					fail("无法读取文件头")
					return
				}
				if string(magic) != "PCO2" {
					deniability = true
					mainStatus = "无法读取头部，假定该卷为可否认卷"
					fin.Close()
					update()
				} else {
					saltBuf := make([]byte, 16)
					if _, err := io.ReadFull(fin, saltBuf); err != nil {
						fin.Close()
						fail("读取 salt 失败")
						return
					}
					var cLen uint16
					var flags byte
					if err := binary.Read(fin, binary.BigEndian, &cLen); err != nil {
						fin.Close()
						fail("读取备注长度失败")
						return
					}
					if err := binary.Read(fin, binary.BigEndian, &flags); err != nil {
						fin.Close()
						fail("读取标志位失败")
						return
					}
					cBuf := make([]byte, cLen)
					if _, err := io.ReadFull(fin, cBuf); err != nil {
						fin.Close()
						fail("读取备注内容失败")
						return
					}
					fin.Close()
					comments = string(cBuf)

					if (flags & 2) != 0 {
						keyfile = true
						keyfileLabel = "需要密钥文件"
					} else {
						keyfileLabel = "不适用"
					}
					if (flags & 4) != 0 {
						keyfileOrdered = true
					}
					update()
				}
			} else {
				mode = "encrypt"
				inputLabel = "1 个文件"
				startLabel = "加密"
				inputFile = names[0]
				outputFile = names[0] + VolumeExt
				update()
			}

			onlyFiles = append(onlyFiles, names[0])
			inputFile = names[0]
			if !isSplit {
				compressTotal += stat.Size()
			}
			update()
		}
	} else {
		mode = "encrypt"
		startLabel = "压缩并加密"

		for _, name := range names {
			stat, err := os.Stat(name)
			if err != nil {
				resetUI()
				fail("无法获取拖入项信息")
				return
			}
			if stat.IsDir() {
				folders++
				onlyFolders = append(onlyFolders, name)
			} else {
				files++
				onlyFiles = append(onlyFiles, name)
				allFiles = append(allFiles, name)
				compressTotal += stat.Size()
				requiredFreeSpace += stat.Size()
				inputLabel = fmt.Sprintf("正在扫描文件……（%s）", sizeify(compressTotal))
				update()
			}
		}

		inputLabel = formatItemCount(files, folders)
		inputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
		outputFile = inputFile + VolumeExt
		update()
	}

	go func() {
		oldInputLabel := inputLabel
		for _, name := range onlyFolders {
			err := filepath.Walk(name, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					allFiles = append(allFiles, path)
					compressTotal += info.Size()
					requiredFreeSpace += info.Size()
					inputLabel = fmt.Sprintf("正在扫描文件……（%s）", sizeify(compressTotal))
					update()
				}
				return nil
			})
			if err != nil {
				resetUI()
				fail("遍历拖入项失败")
				return
			}
		}
		inputLabel = fmt.Sprintf("%s（%s）", oldInputLabel, sizeify(compressTotal))
		scanning = false
		update()
	}()
}

// xorVolume 用 AES-CTR 原地加/解密整个卷（可否认性处理）
func xorVolume(fin, fout *os.File, key, iv []byte, total int64) {
	block, err := aes.NewCipher(key)
	check(err)
	stream := cipher.NewCTR(block, iv[:16])
	done := int64(0)
	for {
		src := make([]byte, MiB)
		size, err := fin.Read(src)
		if err != nil {
			break
		}
		dst := make([]byte, size)
		stream.XORKeyStream(dst, src[:size])
		must(fout.Write(dst))

		done += int64(size)
		progress = float32(float64(done) / float64(total))
		update()
	}
}

// hashKeyfile 将单个密钥文件的 SHA3-256 累加进 h，并更新进度
func hashKeyfile(path string, h hash.Hash, done *int, total int64) {
	fin, err := os.Open(path)
	check(err)
	data := make([]byte, MiB)
	for {
		size, err := fin.Read(data)
		if err != nil {
			break
		}
		must(h.Write(data[:size]))
		*done += size
		progress = float32(*done) / float32(total)
		update()
	}
	check(fin.Close())
}

// zipAbort 关闭并删除临时 zip、重置界面，然后设置红色错误提示
func zipAbort(writer *zip.Writer, file *os.File, status string) {
	writer.Close()
	file.Close()
	os.Remove(inputFile)
	resetUI()
	mainStatus = status
	mainStatusColor = RED
}

func work() {
	popupStatus = "正在准备加密任务……"
	mainStatus = "正在处理……"
	mainStatusColor = WHITE
	working = true
	update()

	// Cryptography values
	var salt []byte       // Argon2 salt, 16 bytes
	var keyfileKey []byte // The SHA3-256 hashes of keyfiles

	var tempZipCipherW cipher.Stream
	var tempZipCipherR cipher.Stream
	var tempZipInUse bool = false
	func() {
		key, iv := make([]byte, 32), make([]byte, 16)
		must(rand.Read(key))
		must(rand.Read(iv))
		block, err := aes.NewCipher(key)
		check(err)
		tempZipCipherW = cipher.NewCTR(block, iv)
		tempZipCipherR = cipher.NewCTR(block, iv)
	}()

	// Combine/compress all files into a .zip file if needed
	if len(allFiles) > 1 || len(onlyFolders) > 0 {
		// Consider case where compressing only one file
		files := allFiles
		if len(allFiles) == 0 {
			files = onlyFiles
		}

		// Get the root directory of the selected files
		var rootDir string
		if len(onlyFolders) > 0 {
			rootDir = filepath.Dir(onlyFolders[0])
		} else {
			rootDir = filepath.Dir(onlyFiles[0])
		}

		// Open a temporary .zip for writing
		inputFile = trimVolumeExt(outputFile) + ".tmp"
		file, err := os.Create(inputFile)
		if err != nil { // Make sure file is writable
			accessDenied("Write")
			return
		}

		// Add each file to the .zip
		tempZip := encryptedZipWriter{
			_w:      file,
			_stream: tempZipCipherW,
		}
		tempZipInUse = true
		writer := zip.NewWriter(&tempZip)
		compressStart = time.Now()
		for i, path := range files {
			progressInfo = fmt.Sprintf("%d/%d", i+1, len(files))
			update()

			// Create file info header (size, last modified, etc.)
			stat, err := os.Stat(path)
			if err != nil {
				zipAbort(writer, file, "无法获取输入文件信息")
				return
			}
			header, err := zip.FileInfoHeader(stat)
			if err != nil {
				zipAbort(writer, file, "创建 zip.FileInfoHeader 失败")
				return
			}
			header.Name = strings.TrimPrefix(path, rootDir)
			header.Name = filepath.ToSlash(header.Name)
			header.Name = strings.TrimPrefix(header.Name, "/")

			if compress {
				header.Method = zip.Deflate
			} else {
				header.Method = zip.Store
			}

			// Open the file for reading
			entry, err := writer.CreateHeader(header)
			if err != nil {
				zipAbort(writer, file, "writer.CreateHeader 失败")
				return
			}
			fin, err := os.Open(path)
			if err != nil {
				zipAbort(writer, file, "Read 操作系统拒绝访问")
				return
			}

			// Use a passthrough to catch compression progress
			passthrough := &compressorProgress{Reader: fin}
			buf := make([]byte, MiB)
			_, err = io.CopyBuffer(entry, passthrough, buf)
			fin.Close()

			if err != nil {
				writer.Close()
				insufficientSpace(nil, file)
				os.Remove(inputFile)
				return
			}

			if !working {
				writer.Close()
				cancel(nil, file)
				os.Remove(inputFile)
				return
			}
		}
		check(writer.Close())
		check(file.Close())
	}

	// Recombine a split file if necessary
	if recombine {
		totalFiles := 0
		totalBytes := int64(0)
		done := 0

		// Find out the number of splitted chunks
		for {
			stat, err := os.Stat(fmt.Sprintf("%s.%d", inputFile, totalFiles))
			if err != nil {
				break
			}
			totalFiles++
			totalBytes += stat.Size()
		}

		// Determine target combined volume path
		combinedPath := outputFile
		if !isVolumeExt(combinedPath) {
			combinedPath = outputFile + VolumeExt
		}

		// Make sure not to overwrite anything
		_, err := os.Stat(combinedPath)
		if err == nil { // File already exists
			mainStatus = "请移除 " + filepath.Base(combinedPath)
			mainStatusColor = RED
			return
		}

		// Create file to combine chunks into
		fout, err := os.Create(combinedPath)
		if err != nil { // Make sure file is writable
			accessDenied("Write")
			return
		}

		// Merge all chunks into one file
		startTime := time.Now()
		for i := range totalFiles {
			fin, err := os.Open(fmt.Sprintf("%s.%d", inputFile, i))
			if err != nil {
				fout.Close()
				os.Remove(combinedPath)
				resetUI()
				accessDenied("Read")
				return
			}

			for {
				if !working {
					cancel(fin, fout)
					os.Remove(combinedPath)
					return
				}

				// Copy from the chunk into the combined volume
				data := make([]byte, MiB)
				read, err := fin.Read(data)
				if err != nil {
					break
				}
				data = data[:read]
				var n int
				n, err = fout.Write(data)
				done += read

				if err != nil || n != len(data) {
					insufficientSpace(fin, fout)
					os.Remove(combinedPath)
					return
				}

				// Update the stats
				progress, speed, eta = statify(int64(done), totalBytes, startTime)
				progressInfo = fmt.Sprintf("%d/%d", i+1, totalFiles)
				popupStatus = fmt.Sprintf("正在重组，速度 %.2f MiB/s（预计剩余 %s）", speed, eta)
				update()
			}
			check(fin.Close())
		}
		check(fout.Close())
		inputFileOld = inputFile
		inputFile = combinedPath
	}

	// Input volume has plausible deniability
	if mode == "decrypt" && deniability {
		popupStatus = "正在移除可否认性保护……"
		progressInfo = ""
		progress = 0
		canCancel = false
		update()

		// Get size of volume for showing progress
		stat, err := os.Stat(inputFile)
		check(err)
		total := stat.Size()

		// Rename input volume to free up the filename
		fin, err := os.Open(inputFile)
		check(err)
		for strings.HasSuffix(inputFile, ".tmp") {
			inputFile = strings.TrimSuffix(inputFile, ".tmp")
		}
		inputFile += ".tmp"
		fout, err := os.Create(inputFile)
		check(err)

		// Get the Argon2 salt and XChaCha20 nonce from input volume
		salt := make([]byte, 16)
		nonce := make([]byte, 24)
		if n, err := fin.Read(salt); err != nil || n != 16 {
			panic(errors.New("从文件读取 16 字节失败"))
		}
		if n, err := fin.Read(nonce); err != nil || n != 24 {
			panic(errors.New("从文件读取 24 字节失败"))
		}

		// Generate key and decrypt the entire volume
		key := argon2.IDKey([]byte(password), salt, 4, 1<<20, 4, 32)
		xorVolume(fin, fout, key, nonce, total)

		check(fin.Close())
		check(fout.Close())

		// Check if the PCO2 magic can be read from the decrypted volume
		fin, err = os.Open(inputFile)
		check(err)
		magic := make([]byte, 4)
		n, err := fin.Read(magic)
		check(fin.Close())
		if err != nil || n != 4 || string(magic) != "PCO2" {
			os.Remove(inputFile)
			inputFile = strings.TrimSuffix(inputFile, ".tmp")
			broken(nil, nil, "密码错误，或该文件不是卷", true)
			if recombine {
				inputFile = inputFileOld
			}
			return
		}
	}

	canCancel = false
	progress = 0
	progressInfo = ""
	update()

	// Subtract the header size from the total size if decrypting
	stat, err := os.Stat(inputFile)
	if err != nil {
		resetUI()
		accessDenied("Read")
		return
	}
	total := stat.Size()

	// Open input file in read-only mode
	fin, err := os.Open(inputFile)
	if err != nil {
		resetUI()
		accessDenied("Read")
		return
	}

	// Setup output file
	var fout *os.File

	// If encrypting, generate values and write to file
	if mode == "encrypt" {
		popupStatus = "正在初始化加密参数……"
		update()

		// Make sure not to overwrite anything
		_, err = os.Stat(outputFile)
		if split && err == nil { // File already exists
			fin.Close()
			if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
				os.Remove(inputFile)
			}
			mainStatus = "请移除 " + filepath.Base(outputFile)
			mainStatusColor = RED
			return
		}

		// Create the output file
		fout, err = os.Create(outputFile + ".incomplete")
		if err != nil {
			fin.Close()
			if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
				os.Remove(inputFile)
			}
			accessDenied("Write")
			return
		}

		salt = make([]byte, 16)
		must(rand.Read(salt))

		headerBuf := make([]byte, 2+1+len(comments))
		binary.BigEndian.PutUint16(headerBuf[0:2], uint16(len(comments)))
		var flagByte byte
		if paranoid {
			flagByte |= 1
		}
		if len(keyfiles) > 0 {
			flagByte |= 2
		}
		if keyfileOrdered {
			flagByte |= 4
		}
		if reedsolo {
			flagByte |= 8
		}
		headerBuf[2] = flagByte
		copy(headerBuf[3:], []byte(comments))

		must(fout.Write([]byte("PCO2")))
		must(fout.Write(salt))
		must(fout.Write(headerBuf))
	} else { // Decrypting, read values from file and decode
		popupStatus = "正在解析文件头……"
		update()

		magic := make([]byte, 4)
		if _, err := io.ReadFull(fin, magic); err != nil || string(magic) != "PCO2" {
			broken(fin, nil, "无效的文件格式或文件头已损坏", true)
			return
		}
		salt = make([]byte, 16)
		if _, err := io.ReadFull(fin, salt); err != nil {
			broken(fin, nil, "读取 salt 失败", true)
			return
		}

		var cLen uint16
		var flagByte byte
		if err := binary.Read(fin, binary.BigEndian, &cLen); err != nil {
			broken(fin, nil, "读取备注长度失败", true)
			return
		}
		if err := binary.Read(fin, binary.BigEndian, &flagByte); err != nil {
			broken(fin, nil, "读取标志位失败", true)
			return
		}
		cBuf := make([]byte, cLen)
		if _, err := io.ReadFull(fin, cBuf); err != nil {
			broken(fin, nil, "读取备注失败", true)
			return
		}
		comments = string(cBuf)

		paranoid = (flagByte & 1) != 0
		reedsolo = (flagByte & 8) != 0
		if deniability {
			keyfile = (flagByte & 2) != 0
			keyfileOrdered = (flagByte & 4) != 0
		}
	}

	popupStatus = "正在生成安全主密钥（Argon2id）……"
	update()

	// Derive encryption keys and subkeys
	var key []byte
	if paranoid {
		key = argon2.IDKey(
			[]byte(password),
			salt,
			8,     // 8 passes
			1<<20, // 1 GiB memory
			8,     // 8 threads
			32,    // 32-byte output key
		)
	} else {
		key = argon2.IDKey(
			[]byte(password),
			salt,
			4,
			1<<20,
			4,
			32,
		)
	}
	if bytes.Equal(key, make([]byte, 32)) {
		panic(errors.New("严重错误：argon2 失败"))
	}

	// If keyfiles are being used
	if len(keyfiles) > 0 || keyfile {
		popupStatus = "正在读取密钥文件……"
		update()

		var keyfileTotal int64
		for _, path := range keyfiles {
			stat, err := os.Stat(path)
			check(err)
			keyfileTotal += stat.Size()
		}

		if keyfileOrdered {
			var tmp = sha3.New256()
			var keyfileDone int
			for _, path := range keyfiles {
				hashKeyfile(path, tmp, &keyfileDone, keyfileTotal)
			}
			keyfileKey = tmp.Sum(nil)
		} else {
			var keyfileDone int
			for _, path := range keyfiles {
				tmp := sha3.New256()
				hashKeyfile(path, tmp, &keyfileDone, keyfileTotal)
				sum := tmp.Sum(nil)
				if keyfileKey == nil {
					keyfileKey = sum
				} else {
					for i, j := range sum {
						keyfileKey[i] ^= j
					}
				}
			}
		}
	}

	if mode == "decrypt" {
		fout, err = os.Create(outputFile + ".incomplete")
		if err != nil {
			fin.Close()
			if recombine {
				os.Remove(inputFile)
			}
			accessDenied("Write")
			return
		}
	}

	if len(keyfiles) > 0 || keyfile {
		// Prevent an even number of duplicate keyfiles
		if bytes.Equal(keyfileKey, make([]byte, 32)) {
			mainStatus = "检测到重复的密钥文件"
			mainStatusColor = RED
			fin.Close()
			if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
				os.Remove(inputFile)
			}
			fout.Close()
			os.Remove(fout.Name())
			return
		}

		// XOR the encryption key with the keyfile key
		tmp := key
		key = make([]byte, 32)
		for i := range key {
			key[i] = tmp[i] ^ keyfileKey[i]
		}
	}
	aead, err := chacha20poly1305.NewX(key)
	check(err)

	var rsCodec reedsolomon.Encoder
	if reedsolo {
		rsCodec, err = reedsolomon.New(10, 2)
		check(err)
	}

	canCancel = true
	startTime := time.Now()
	tempZip := encryptedZipReader{_r: fin, _stream: tempZipCipherR}

	var chunkIdx uint64
	done := int64(0)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	aad := make([]byte, 8)

	defer func() {
		// Securely wipe sensitive keys from RAM
		for i := range key {
			key[i] = 0
		}
		for i := range nonce {
			nonce[i] = 0
		}
		if keyfileKey != nil {
			for i := range keyfileKey {
				keyfileKey[i] = 0
			}
		}
	}()

	if mode == "encrypt" {
		buf := make([]byte, MiB)
		for {
			if !working {
				cancel(fin, fout)
				if recombine || len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
					os.Remove(inputFile)
				}
				os.Remove(fout.Name())
				return
			}
			var read int
			if tempZipInUse {
				read, err = tempZip.Read(buf)
			} else {
				read, err = fin.Read(buf)
			}
			if err != nil || read == 0 {
				break
			}
			chunk := buf[:read]

			binary.BigEndian.PutUint64(nonce[0:8], chunkIdx)
			binary.BigEndian.PutUint64(aad[0:8], chunkIdx)
			ct := aead.Seal(nil, nonce, chunk, aad)

			if reedsolo {
				const dataShards = 10
				const parityShards = 2
				const totalShards = 12
				shardSize := (len(ct) + dataShards - 1) / dataShards
				paddedCt := make([]byte, shardSize*dataShards)
				copy(paddedCt, ct)

				shards := make([][]byte, totalShards)
				for i := 0; i < dataShards; i++ {
					shards[i] = paddedCt[i*shardSize : (i+1)*shardSize]
				}
				for i := dataShards; i < totalShards; i++ {
					shards[i] = make([]byte, shardSize)
				}
				check(rsCodec.Encode(shards))

				check(binary.Write(fout, binary.BigEndian, uint32(len(ct))))
				check(binary.Write(fout, binary.BigEndian, uint32(shardSize)))
				for i := 0; i < totalShards; i++ {
					sum := crc32.ChecksumIEEE(shards[i])
					check(binary.Write(fout, binary.BigEndian, sum))
					must(fout.Write(shards[i]))
				}
			} else {
				check(binary.Write(fout, binary.BigEndian, uint32(len(ct))))
				must(fout.Write(ct))
			}

			chunkIdx++
			done += int64(read)
			progress, speed, eta = statify(done, total, startTime)
			progressInfo = fmt.Sprintf("%.2f%%", progress*100)
			popupStatus = fmt.Sprintf("正在加密，速度 %.2f MiB/s（预计剩余 %s）", speed, eta)
			update()
		}
	} else { // mode == "decrypt"
		for {
			if !working {
				cancel(fin, fout)
				if recombine {
					os.Remove(inputFile)
				}
				os.Remove(fout.Name())
				return
			}

			var ctLen uint32
			if err := binary.Read(fin, binary.BigEndian, &ctLen); err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					break
				}
				broken(fin, fout, "读取密文块长度失败", false)
				return
			}

			binary.BigEndian.PutUint64(nonce[0:8], chunkIdx)
			binary.BigEndian.PutUint64(aad[0:8], chunkIdx)
			var plain []byte

			if reedsolo {
				var shardSize uint32
				if err := binary.Read(fin, binary.BigEndian, &shardSize); err != nil {
					broken(fin, fout, "读取纠错分块信息失败", false)
					return
				}
				if shardSize == 0 || shardSize > 5*MiB {
					broken(fin, fout, "纠错分块大小异常", false)
					return
				}

				const dataShards = 10
				const parityShards = 2
				const totalShards = 12
				shards := make([][]byte, totalShards)
				for i := 0; i < totalShards; i++ {
					var storedSum uint32
					if err := binary.Read(fin, binary.BigEndian, &storedSum); err != nil {
						broken(fin, fout, "读取纠错分块校验失败", false)
						return
					}
					shards[i] = make([]byte, shardSize)
					if _, err := io.ReadFull(fin, shards[i]); err != nil {
						broken(fin, fout, "读取纠错分块失败", false)
						return
					}
					if crc32.ChecksumIEEE(shards[i]) != storedSum {
						// Mark corrupt shard as missing for RS Reconstruct
						shards[i] = nil
					}
				}

				if err := rsCodec.Reconstruct(shards); err != nil {
					// Could not reconstruct
				}

				fullBuf := make([]byte, 0, int(shardSize)*dataShards)
				for i := 0; i < dataShards; i++ {
					if shards[i] != nil {
						fullBuf = append(fullBuf, shards[i]...)
					}
				}
				if int(ctLen) <= len(fullBuf) {
					candidateCt := fullBuf[:ctLen]
					p, decErr := aead.Open(nil, nonce, candidateCt, aad)
					if decErr == nil {
						plain = p
					}
				}
				if plain == nil {
					if keep {
						kept = true
					} else {
						broken(fin, fout, "输入文件已严重损坏且无法恢复", false)
						return
					}
				}
			} else {
				ct := make([]byte, ctLen)
				if _, err := io.ReadFull(fin, ct); err != nil {
					broken(fin, fout, "读取密文内容失败", false)
					return
				}
				p, decErr := aead.Open(nil, nonce, ct, aad)
				if decErr != nil {
					if keep {
						kept = true
					} else {
						broken(fin, fout, "密文校验失败：密码错误或内容已损坏", false)
						return
					}
				} else {
					plain = p
				}
			}

			if len(plain) > 0 {
				must(fout.Write(plain))
			}
			chunkIdx++
			done += MiB
			if done > total {
				done = total
			}
			progress, speed, eta = statify(done, total, startTime)
			progressInfo = fmt.Sprintf("%.2f%%", progress*100)
			popupStatus = fmt.Sprintf("正在解密，速度 %.2f MiB/s（预计剩余 %s）", speed, eta)
			update()
		}
	}

	check(fin.Close())
	check(fout.Close())

	// If destination file already exists, remove it before renaming (Windows compatibility)
	if _, err := os.Stat(outputFile); err == nil {
		_ = os.Remove(outputFile)
	}
	check(os.Rename(outputFile+".incomplete", outputFile))

	// Add plausible deniability
	if mode == "encrypt" && deniability {
		popupStatus = "正在添加可否认性……"
		canCancel = false
		update()

		// Get size of volume for showing progress
		stat, err := os.Stat(outputFile)
		check(err)
		total := stat.Size()

		// Rename the output volume to free up the filename
		os.Rename(outputFile, outputFile+".tmp")
		fin, err := os.Open(outputFile + ".tmp")
		check(err)
		fout, err := os.Create(outputFile + ".incomplete")
		check(err)

		// Use a random Argon2 salt and XChaCha20 nonce
		salt := make([]byte, 16)
		nonce := make([]byte, 24)
		if n, err := rand.Read(salt); err != nil || n != 16 {
			panic(errors.New("严重错误：crypto/rand 失败"))
		}
		if n, err := rand.Read(nonce); err != nil || n != 24 {
			panic(errors.New("严重错误：crypto/rand 失败"))
		}
		if bytes.Equal(salt, make([]byte, 16)) || bytes.Equal(nonce, make([]byte, 24)) {
			panic(errors.New("严重错误：crypto/rand 失败"))
		}
		must(fout.Write(salt))
		must(fout.Write(nonce))

		// Generate key and XChaCha20
		key := argon2.IDKey([]byte(password), salt, 4, 1<<20, 4, 32)
		if bytes.Equal(key, make([]byte, 32)) {
			panic(errors.New("严重错误：argon2 失败"))
		}

		// Encrypt the entire volume
		xorVolume(fin, fout, key, nonce, total)

		check(fin.Close())
		check(fout.Close())
		check(os.Remove(fin.Name()))
		check(os.Rename(outputFile+".incomplete", outputFile))
		canCancel = true
		update()
	}

	// Split the file into chunks
	if split {
		var splitted []string
		stat, err := os.Stat(outputFile)
		check(err)
		size := stat.Size()
		finishedFiles := 0
		finishedBytes := 0
		chunkSize, err := strconv.Atoi(splitSize)
		if err != nil || chunkSize <= 0 {
			chunkSize = 1
		}

		// Calculate chunk size
		if splitSelected == 0 {
			chunkSize *= KiB
		} else if splitSelected == 1 {
			chunkSize *= MiB
		} else if splitSelected == 2 {
			chunkSize *= GiB
		} else if splitSelected == 3 {
			chunkSize *= TiB
		} else {
			parts := chunkSize
			chunkSize = int(math.Ceil(float64(size) / float64(parts)))
		}
		if chunkSize <= 0 {
			chunkSize = 1
		}

		// Get the number of required chunks
		chunks := int(math.Ceil(float64(size) / float64(chunkSize)))
		if chunks <= 0 {
			chunks = 1
		}
		progressInfo = fmt.Sprintf("%d/%d", finishedFiles+1, chunks)
		update()

		// Open the volume for reading
		fin, err := os.Open(outputFile)
		check(err)

		// Delete existing chunks to prevent mixed chunks
		names, err := filepath.Glob(outputFile + ".*")
		check(err)
		for _, i := range names {
			check(os.Remove(i))
		}

		// Start the splitting process
		startTime := time.Now()
		for i := range chunks {
			// Make the chunk
			fout, _ := os.Create(fmt.Sprintf("%s.%d.incomplete", outputFile, i))
			done := 0

			// Copy data into the chunk
			for {
				data := make([]byte, MiB)
				for done+len(data) > chunkSize {
					data = make([]byte, int(math.Ceil(float64(len(data))/2)))
				}

				read, err := fin.Read(data)
				if err != nil {
					break
				}
				if !working {
					cancel(fin, fout)
					if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
						os.Remove(inputFile)
					}
					os.Remove(outputFile)
					for _, j := range splitted { // Remove existing chunks
						os.Remove(j)
					}
					os.Remove(fmt.Sprintf("%s.%d", outputFile, i))
					return
				}

				data = data[:read]
				_, err = fout.Write(data)
				if err != nil {
					insufficientSpace(fin, fout)
					if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
						os.Remove(inputFile)
					}
					os.Remove(outputFile)
					for _, j := range splitted { // Remove existing chunks
						os.Remove(j)
					}
					os.Remove(fmt.Sprintf("%s.%d", outputFile, i))
					return
				}
				done += read
				if done >= chunkSize {
					break
				}

				// Update stats
				finishedBytes += read
				progress, speed, eta = statify(int64(finishedBytes), int64(size), startTime)
				popupStatus = fmt.Sprintf("正在分块，速度 %.2f MiB/s（预计剩余 %s）", speed, eta)
				update()
			}
			check(fout.Close())

			// Update stats
			finishedFiles++
			if finishedFiles == chunks {
				finishedFiles--
			}
			splitted = append(splitted, fmt.Sprintf("%s.%d", outputFile, i))
			progressInfo = fmt.Sprintf("%d/%d", finishedFiles+1, chunks)
			update()
		}

		check(fin.Close())
		check(os.Remove(outputFile))
		names, err = filepath.Glob(outputFile + ".*.incomplete")
		check(err)
		for _, i := range names {
			check(os.Rename(i, strings.TrimSuffix(i, ".incomplete")))
		}
	}

	canCancel = false
	progress = 0
	progressInfo = ""
	update()

	// Delete temporary files used during encryption and decryption
	if recombine || len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
		_ = os.Remove(inputFile)
		if deniability {
			_ = os.Remove(strings.TrimSuffix(inputFile, ".tmp"))
		}
	}

	// Delete the input files if the user chooses
	if delete_ {
		popupStatus = "正在删除文件……"
		update()

		if mode == "decrypt" {
			if recombine { // Remove each chunk of volume
				i := 0
				for {
					_, err := os.Stat(fmt.Sprintf("%s.%d", inputFileOld, i))
					if err != nil {
						break
					}
					_ = os.Remove(fmt.Sprintf("%s.%d", inputFileOld, i))
					i++
				}
			} else {
				_ = os.Remove(inputFile)
				if deniability {
					_ = os.Remove(strings.TrimSuffix(inputFile, ".tmp"))
				}
			}
		} else {
			for _, i := range onlyFiles {
				_ = os.Remove(i)
			}
			for _, i := range onlyFolders {
				_ = os.RemoveAll(i)
			}
		}
	}
	if mode == "decrypt" && deniability {
		_ = os.Remove(inputFile)
	}

	if mode == "decrypt" && !kept && autoUnzip {
		showProgress = true
		popupStatus = "正在解压……"
		update()

		if err := unpackArchive(outputFile); err != nil {
			fail("自动解压失败！")
			return
		}

		check(os.Remove(outputFile))
	}

	// All done, reset the UI
	oldKept := kept
	resetUI()
	kept = oldKept

	// If the user chose to keep a corrupted/modified file, let them know
	if kept {
		mainStatus = "输入文件已被修改，请小心"
		mainStatusColor = YELLOW
	} else {
		mainStatus = "已完成"
		mainStatusColor = GREEN
	}
}

// If the OS denies reading or writing to a file
func accessDenied(s string) {
	mainStatus = s + " 操作系统拒绝访问"
	mainStatusColor = RED
}

// If there isn't enough disk space
func insufficientSpace(fin *os.File, fout *os.File) {
	if fin != nil {
		fin.Close()
	}
	if fout != nil {
		fout.Close()
	}
	mainStatus = "磁盘空间不足"
	mainStatusColor = RED
}

// If corruption is detected during decryption
func broken(fin *os.File, fout *os.File, message string, keepOutput bool) {
	if fin != nil {
		fin.Close()
	}
	if fout != nil {
		fout.Close()
	}
	mainStatus = message
	mainStatusColor = RED

	// Clean up temporary incomplete file since decryption failed
	if recombine {
		os.Remove(inputFile)
	}
	if !keepOutput && fout != nil {
		os.Remove(fout.Name())
	}
}

// Stop working if user hits "取消"
func cancel(fin *os.File, fout *os.File) {
	if fin != nil {
		fin.Close()
	}
	if fout != nil {
		fout.Close()
	}
	mainStatus = "用户已取消操作"
	mainStatusColor = WHITE
}

// Reset the UI to a clean state with nothing selected or checked
func resetUI() {
	mode = ""

	inputFile = ""
	inputFileOld = ""
	outputFile = ""
	onlyFiles = nil
	onlyFolders = nil
	allFiles = nil
	inputLabel = "将文件或文件夹拖入此窗口"

	password = ""
	cpassword = ""
	showPassword = false
	passwordStateLabel = "显示"

	passgenLength = 10
	passgenUpper = true
	passgenLower = true
	passgenNums = true
	passgenSymbols = true
	passgenCopy = true

	keyfile = false
	keyfiles = nil
	keyfileOrdered = false
	keyfileLabel = "未选择"

	comments = ""
	commentsLabel = "备注："
	commentsDisabled = false

	paranoid = false
	reedsolo = false
	deniability = false
	recursively = false
	split = false
	splitSize = ""
	splitSelected = 1
	recombine = false
	compress = false
	delete_ = false
	autoUnzip = false
	sameLevel = false
	keep = false
	kept = false

	startLabel = "开始"
	mainStatus = "就绪"
	mainStatusColor = WHITE
	popupStatus = ""
	requiredFreeSpace = 0

	progress = 0
	progressInfo = ""
	update()
}

// Generate a cryptographically secure password
func genPassword() string {
	chars := ""
	if passgenUpper {
		chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if passgenLower {
		chars += "abcdefghijklmnopqrstuvwxyz"
	}
	if passgenNums {
		chars += "1234567890"
	}
	if passgenSymbols {
		chars += "-=_+!@#$^&()?<>"
	}
	if chars == "" {
		chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
	}
	tmp := make([]byte, int(passgenLength))
	for i := 0; i < int(passgenLength); i++ {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		tmp[i] = chars[j.Int64()]
	}
	if passgenCopy {
		writeClipboard(string(tmp))
	}
	return string(tmp)
}

// Convert done, total, and starting time to progress, speed, and ETA
func statify(done int64, total int64, start time.Time) (float32, float64, string) {
	var progress float32
	if total > 0 {
		progress = float32(done) / float32(total)
	}
	elapsedSec := time.Since(start).Seconds()
	if elapsedSec <= 0.0001 {
		elapsedSec = 0.0001
	}
	speed := (float64(done) / float64(MiB)) / elapsedSec

	var eta int
	if speed > 0 && total >= done {
		remainingBytes := float64(total - done)
		remainingSec := remainingBytes / (speed * float64(MiB))
		if !math.IsNaN(remainingSec) && !math.IsInf(remainingSec, 0) && remainingSec < 8640000 {
			eta = int(remainingSec)
		}
	}
	return float32(math.Min(math.Max(float64(progress), 0), 1)), speed, timeify(eta)
}

// Convert seconds to HH:MM:SS
func timeify(seconds int) string {
	if seconds < 0 {
		seconds = 0
	}
	hours := seconds / 3600
	seconds %= 3600
	minutes := seconds / 60
	seconds %= 60
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

// Convert bytes to KiB, MiB, etc.
func sizeify(size int64) string {
	if size >= int64(TiB) {
		return fmt.Sprintf("%.2f TiB", float64(size)/float64(TiB))
	} else if size >= int64(GiB) {
		return fmt.Sprintf("%.2f GiB", float64(size)/float64(GiB))
	} else if size >= int64(MiB) {
		return fmt.Sprintf("%.2f MiB", float64(size)/float64(MiB))
	} else {
		return fmt.Sprintf("%.2f KiB", float64(size)/float64(KiB))
	}
}

func unpackArchive(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	var totalSize int64
	for _, f := range reader.File {
		totalSize += int64(f.UncompressedSize64)
	}

	extractDir := filepath.Dir(zipPath)
	if !sameLevel {
		extractDir = filepath.Join(extractDir, strings.TrimSuffix(filepath.Base(zipPath), ".zip"))
	}
	cleanExtractDir := filepath.Clean(extractDir)

	var done int64
	startTime := time.Now()
	buffer := make([]byte, MiB)

	for i, f := range reader.File {
		outPath := filepath.Join(cleanExtractDir, f.Name)
		cleanOutPath := filepath.Clean(outPath)
		// 防御 Zip Slip 目录穿越：解压路径必须包含在 cleanExtractDir 之下
		if !strings.HasPrefix(cleanOutPath, cleanExtractDir+string(os.PathSeparator)) && cleanOutPath != cleanExtractDir {
			return errors.New("潜在的恶意 zip 项路径（检测到目录穿越）")
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(cleanOutPath, 0700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(cleanOutPath), 0700); err != nil {
			return err
		}

		fileInArchive, err := f.Open()
		if err != nil {
			return err
		}
		dstFile, err := os.Create(cleanOutPath)
		if err != nil {
			fileInArchive.Close()
			return err
		}

		for {
			n, readErr := fileInArchive.Read(buffer)
			if n > 0 {
				if _, writeErr := dstFile.Write(buffer[:n]); writeErr != nil {
					dstFile.Close()
					fileInArchive.Close()
					os.Remove(cleanOutPath)
					return writeErr
				}
				done += int64(n)
				progress, speed, eta = statify(done, totalSize, startTime)
				progressInfo = fmt.Sprintf("%d/%d", i+1, len(reader.File))
				popupStatus = fmt.Sprintf("正在解包，速度 %.2f MiB/s（预计剩余 %s）", speed, eta)
				update()
			}
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				dstFile.Close()
				fileInArchive.Close()
				return readErr
			}
		}
		dstFile.Close()
		fileInArchive.Close()
	}
	return nil
}
