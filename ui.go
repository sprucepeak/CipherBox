package main

/*

   Native UI 视图层：
   - 整窗拖放区、密码区（强度环/确认环）、密钥文件、备注
   - 高级选项（偏执/压缩/RS 码/删除/可否认性/递归/分块 与 解密侧选项）
   - 保存输出、开始按钮、状态行
   - 四个弹窗：生成密码 / 管理密钥文件 / 覆盖确认 / 进度

*/

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Picocrypt/zxcvbn-go"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/transfer"
	"github.com/egoist/mygo/ui"
)

// UI-only state
var showPassword bool          // 密码可见性状态
var splitUnitStr = "MiB"       // 分块单位选择
var passgenSlider float64 = 10 // 密码生成滑块绑定长度

// 剪贴板
func writeClipboard(s string) {
	_ = mygo.Clipboard.Write(transfer.New(transfer.NewItem(transfer.Bytes(transfer.Text, []byte(s)))))
}

func readClipboard() string {
	if data, err := mygo.Clipboard.Read(transfer.Text); err == nil {
		if b, err := data.Read(transfer.Text); err == nil {
			return string(b)
		}
	}
	return ""
}

func indexOf(s string, list []string) int32 {
	for i, v := range list {
		if v == s {
			return int32(i)
		}
	}
	return 0
}

func defaultStartDir() string {
	if len(onlyFiles) > 0 {
		return filepath.Dir(onlyFiles[0])
	}
	if len(onlyFolders) > 0 {
		return filepath.Dir(onlyFolders[0])
	}
	wd, _ := os.Getwd()
	return wd
}

// 输出文件只读展示文本
func outLabel() string {
	if outputFile == "" {
		return ""
	}
	if recursively {
		return "（多个值）"
	}
	tmp := filepath.Base(outputFile)
	if split {
		tmp += ".*"
	}
	return tmp
}

// 过滤非法字符：仅允许生成密码支持的 ASCII 字符集（大写、小写、数字、指定符号），拒绝中文及非白名单字符
func sanitizePassword(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			sb.WriteRune(r)
		case r >= 'a' && r <= 'z':
			sb.WriteRune(r)
		case r >= '0' && r <= '9':
			sb.WriteRune(r)
		case strings.ContainsRune("-=_+!@#$^&()?<>/~`*%,.;:[]{}|'\"", r):
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// 密码强度环 / 确认环指示器
func strengthRing(c *ui.Context, frac float32, col ui.Color) ui.Element {
	return ui.Box(c).Size(20, 20).Draw(func(p *ui.Painter, r ui.Rect) {
		if col == TRANSPARENT || frac <= 0 {
			return
		}
		cx := r.X + r.W/2
		cy := r.Y + r.H/2
		radius := float64(r.W/2 - 2)
		var path ui.Path
		if frac >= 1 {
			path.Circle(cx, cy, float32(radius))
		} else {
			const segs = 48
			a0 := -math.Pi / 2
			a1 := a0 + 2*math.Pi*float64(frac)
			path.MoveTo(cx+float32(radius*math.Cos(a0)), cy+float32(radius*math.Sin(a0)))
			for i := 1; i <= segs; i++ {
				a := a0 + (a1-a0)*float64(i)/segs
				path.LineTo(cx+float32(radius*math.Cos(a)), cy+float32(radius*math.Sin(a)))
			}
		}
		p.StrokePath(&path, 2.5, col)
	})
}

// 改进的多维度密码强度计算：结合长度、字符集多样性、熵值与 zxcvbn 字典评估
func evaluatePasswordStrength(p string) (int, float32, ui.Color) {
	if len(p) == 0 {
		return 0, 0, TRANSPARENT
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range p {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	variety := 0
	if hasUpper {
		variety++
	}
	if hasLower {
		variety++
	}
	if hasDigit {
		variety++
	}
	if hasSpecial {
		variety++
	}

	zScore := zxcvbn.PasswordStrength(p, nil).Score // 0..4
	l := len(p)

	var score int
	switch {
	case l < 6:
		score = 0
	case l < 8:
		if variety >= 3 && zScore >= 2 {
			score = 1
		} else {
			score = 0
		}
	case l < 12:
		if variety >= 3 && zScore >= 3 {
			score = 3
		} else if variety >= 2 && zScore >= 2 {
			score = 2
		} else {
			score = 1
		}
	case l < 16:
		if variety >= 3 && zScore >= 3 {
			score = 4
		} else if variety >= 2 {
			score = 3
		} else {
			score = 2
		}
	default: // >= 16 字符
		if variety >= 2 && zScore >= 3 {
			score = 4
		} else if variety >= 2 {
			score = 3
		} else {
			score = 2
		}
	}

	// 计算圆环展示比例与高辨识度配色
	var frac float32
	var col ui.Color
	switch score {
	case 0:
		frac = 0.2
		col = ui.RGBA(0xd9, 0x53, 0x4f, 1) // 红
	case 1:
		frac = 0.4
		col = ui.RGBA(0xf0, 0xad, 0x4e, 1) // 橙黄
	case 2:
		frac = 0.65
		col = ui.RGBA(0x5b, 0xc0, 0xde, 1) // 青蓝
	case 3:
		frac = 0.85
		col = ui.RGBA(0x5c, 0xb8, 0x5c, 1) // 浅绿
	default:
		frac = 1.0
		col = ui.RGBA(0x28, 0xa7, 0x45, 1) // 翠绿
	}
	return score, frac, col
}

// labelColor 标签取色：禁用态用弱化文字色，否则正常文字色
func labelColor(t *ui.Theme, disabled bool) ui.Color {
	if disabled {
		return t.TextMuted
	}
	return t.Text
}

// 开始按钮文案
func startButtonLabel() string {
	if !recursively {
		return startLabel
	}
	return "处理"
}

// ─── 弹窗 ───────────────────────────────────────────────

func passgenModal(c *ui.Context) {
	ui.Modal(c, &showPassgen, func() {
		t := c.Theme()
		ui.Column(c).Padding(16).Gap(8).Children(func() {
			ui.Text(c, "生成密码").Bold()
			ui.Row(c).Gap(8).Children(func() {
				ui.Text(c, "长度：")
				ui.Slider(c, &passgenSlider, 8, 64).Grow(1).OnChange(func() {
					passgenLength = passgenSlider
					update()
				})
				ui.Text(c, strconv.Itoa(int(passgenSlider))).TextColor(t.TextMuted)
			})
			ui.Checkbox(c, &passgenUpper, "大写字母")
			ui.Checkbox(c, &passgenLower, "小写字母")
			ui.Checkbox(c, &passgenNums, "数字（0-9）")
			ui.Checkbox(c, &passgenSymbols, "符号（-=_+!@#$^&()<>）").Tooltip("支持的符号：- = _ + ! @ # $ ^ & ( ) ? < >")
			ui.Checkbox(c, &passgenCopy, "复制到剪贴板")
			ui.Row(c).Gap(8).Children(func() {
				ui.Button(c, "取消").OnClick(func() {
					showPassgen = false
				})
				ui.Button(c, "生成").Disabled(!(passgenUpper || passgenLower || passgenNums || passgenSymbols)).OnClick(func() {
					password = genPassword()
					cpassword = password
					passwordStrength, _, _ = evaluatePasswordStrength(password)
					showPassword = true
					passwordStateLabel = "隐藏"
					showPassgen = false
					update()
				})
			})
		}).Background(t.Surface)
	})
}

func keyfileModal(c *ui.Context) {
	ui.Modal(c, &showKeyfile, func() {
		t := c.Theme()
		ui.Column(c).Padding(16).Gap(8).Children(func() {
			ui.Text(c, "管理密钥文件").Bold()

			// 拖放区
			zone := ui.Box(c).MinHeight(56).Grow(1).Padding(12).Border(1, t.Border)
			opts := transfer.DropOptions{Formats: []transfer.Format{transfer.FileList}}
			if _, over := ui.DataDragOver(zone, opts); over {
				zone.Border(1, t.Accent).Background(t.Surface)
			}
			zone.Children(func() {
				ui.Text(c, "将密钥文件拖到此处").TextColor(t.TextMuted)
			})
			if drop, ok := ui.DropData(zone, opts); ok {
				if files, err := drop.Data.Files(); err == nil && len(files) > 0 {
					onDrop(files)
				}
			}

			if mode != "decrypt" {
				ui.Checkbox(c, &keyfileOrdered, "要求正确的顺序").Tooltip("密钥文件的顺序很重要")
			} else if keyfileOrdered {
				ui.Text(c, "需要正确的顺序")
			}
			for _, k := range keyfiles {
				ui.Text(c, filepath.Base(k))
			}
			ui.Row(c).Gap(8).Children(func() {
				ui.Button(c, "清除").Tooltip("移除所有密钥文件").OnClick(func() {
					keyfiles = nil
					if keyfile {
						keyfileLabel = "需要密钥文件"
					} else {
						keyfileLabel = "未选择"
					}
					update()
				})
				ui.Button(c, "完成").OnClick(func() {
					showKeyfile = false
				})
			})
		}).Background(t.Surface)
	})
}

func overwriteModal(c *ui.Context) {
	ui.Modal(c, &showOverwrite, func() {
		t := c.Theme()
		ui.Column(c).Padding(16).Gap(10).Children(func() {
			ui.Text(c, "文件已存在提示").Bold()
			targetName := filepath.Base(outputFile)
			if targetName == "" {
				targetName = "目标文件"
			}
			msg := fmt.Sprintf("目标文件 \"%s\" 已经存在，是否确定覆盖？", targetName)
			if mode == "decrypt" {
				msg = fmt.Sprintf("解密目标 \"%s\" 已存在。\n确定覆盖吗？（密码验证失败前不会损坏原文件）", targetName)
			}
			ui.Text(c, msg)
			ui.Row(c).Gap(8).Children(func() {
				ui.Button(c, "取消").OnClick(func() {
					showOverwrite = false
				})
				ui.Button(c, "确定覆盖").OnClick(func() {
					showOverwrite = false

					showProgress = true
					canCancel = true
					go func() {
						work()
						working = false
						showProgress = false
						update()
					}()
				})
			})
		}).Background(t.Surface)
	})
}

func progressModal(c *ui.Context) {
	ui.Modal(c, &showProgress, func() {
		t := c.Theme()
		ui.Column(c).Padding(16).Gap(10).Children(func() {
			ui.Text(c, "进度").Bold()
			ui.Row(c).Gap(8).Children(func() {
				ui.Meter(c, float64(progress), 0, 1, nil).Grow(1)
				ui.Button(c, func() string {
					if working {
						return "取消"
					}
					return "..."
				}()).Disabled(!canCancel).OnClick(func() {
					working = false
					canCancel = false
				})
			})
			ui.Text(c, popupStatus).Wrap()
			if progressInfo != "" {
				ui.Text(c, progressInfo).TextColor(t.TextMuted)
			}
		}).Background(t.Surface)
	})
}

// ─── 对话框操作 ─────────────────────────────────────────

func createKeyfile() {
	f := mygo.SaveDialogOptions{
		Title: "选择密钥文件保存位置",
		DefaultPath: filepath.Join(defaultStartDir(),
			"keyfile-"+strconv.Itoa(int(time.Now().Unix()))+".bin"),
	}
	file, err := mygo.Dialog.Save(f)
	if file == "" || err != nil {
		return
	}

	fout, err := os.Create(file)
	if err != nil {
		fail("创建密钥文件失败")
		return
	}
	data := make([]byte, 32)
	if n, err := rand.Read(data); err != nil || n != 32 {
		panic(errors.New("严重错误：crypto/rand 失败"))
	}
	n, err := fout.Write(data)
	if err != nil || n != 32 {
		fout.Close()
		panic(errors.New("写入完整密钥文件失败"))
	}
	check(fout.Close())
	mainStatus = "就绪"
	mainStatusColor = WHITE
	update()
}

func chooseOutput() {
	f := mygo.SaveDialogOptions{
		Title:       "选择输出保存位置（不要包含扩展名）",
		DefaultPath: defaultStartDir(),
	}

	// Prefill the filename
	tmp := trimVolumeExt(filepath.Base(outputFile))
	f.DefaultPath = filepath.Join(defaultStartDir(), strings.TrimSuffix(tmp, filepath.Ext(tmp)))
	if mode == "encrypt" && (len(allFiles) > 1 || len(onlyFolders) > 0 || compress) {
		f.DefaultPath = filepath.Join(defaultStartDir(), "encrypted-"+strconv.Itoa(int(time.Now().Unix())))
	}

	// Get the chosen file path
	file, err := mygo.Dialog.Save(f)
	if file == "" || err != nil {
		return
	}
	file = filepath.Join(filepath.Dir(file), strings.Split(filepath.Base(file), ".")[0])

	// Add the correct extensions
	if mode == "encrypt" {
		if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
			file += ".zip" + VolumeExt
		} else {
			file += filepath.Ext(inputFile) + VolumeExt
		}
	} else {
		if strings.HasSuffix(inputFile, ".zip"+VolumeExt) || strings.HasSuffix(inputFile, ".zip.pcv") {
			file += ".zip"
		} else {
			tmp := trimVolumeExt(filepath.Base(inputFile))
			file += filepath.Ext(tmp)
		}
	}
	outputFile = file
	mainStatus = "就绪"
	mainStatusColor = WHITE
	update()
}

// ─── 主视图 ─────────────────────────────────────────────

func view(c *ui.Context) {
	invalidate = c.Invalidate
	t := c.Theme()

	// 分块单位与选中索引保持同步（逻辑侧只用 splitSelected）
	if int(splitSelected) < len(splitUnits) && splitUnitStr != splitUnits[splitSelected] {
		splitUnitStr = splitUnits[splitSelected]
	}
	passgenSlider = passgenLength

	// 整个窗口作为全局文件拖拽接收区
	root := ui.Column(c).Fill().Padding(0).Gap(0)
	dropOpts := transfer.DropOptions{Formats: []transfer.Format{transfer.FileList}}
	if _, over := ui.DataDragOver(root, dropOpts); over {
		root.Border(2, t.Accent)
	}
	root.Children(func() {
		// 弹窗
		passgenModal(c)
		keyfileModal(c)
		overwriteModal(c)
		progressModal(c)

		// 主内容区：紧凑无垂直滚动条，满足最小高度完整显示
		ui.Column(c).Grow(1).Padding(12).Gap(6).Children(func() {

			noInput := (len(allFiles) == 0 && len(onlyFiles) == 0) || scanning
			advancedDisabled := (len(keyfiles) == 0 && password == "") || (mode == "encrypt" && password != cpassword)

			// 输入概览 + 清除
			ui.Row(c).Gap(6).Children(func() {
				ui.Text(c, inputLabel).Grow(1).TextColor(labelColor(t, noInput))
				ui.Button(c, "清除").Disabled(noInput).Tooltip("清除所有输入文件并重置界面状态").OnClick(resetUI)
			})

			ui.Divider(c)

			// 密码区：标题与常用快捷操作同行动线
			ui.Row(c).Gap(6).Children(func() {
				ui.Text(c, "密码：").Grow(1).TextColor(labelColor(t, noInput))
				ui.Button(c, passwordStateLabel).Disabled(noInput).Tooltip("切换密码可见性").OnClick(func() {
					showPassword = !showPassword
					if showPassword {
						passwordStateLabel = "隐藏"
					} else {
						passwordStateLabel = "显示"
					}
					update()
				})
				ui.Button(c, "粘贴").Disabled(noInput).Tooltip("从剪贴板粘贴密码").OnClick(func() {
					tmp := sanitizePassword(readClipboard())
					password = tmp
					if mode != "decrypt" {
						cpassword = tmp
					}
					passwordStrength, _, _ = evaluatePasswordStrength(password)
					update()
				})
				ui.Button(c, "生成").Disabled(noInput || mode == "decrypt").Tooltip("生成强随机密码").OnClick(func() {
					showPassgen = true
					update()
				})
				ui.Button(c, "清空").Disabled(noInput).Tooltip("清除密码").OnClick(func() {
					password = ""
					cpassword = ""
					update()
				})
			})

			// 密码输入框 + 强度环（右侧保留固定 20px 环位，保证输入框宽度一致）
			ui.Row(c).Gap(6).Children(func() {
				pw := ui.TextInput(c, &password).Grow(1).OnChange(func() {
					cleaned := sanitizePassword(password)
					if cleaned != password {
						password = cleaned
					}
					passwordStrength, _, _ = evaluatePasswordStrength(password)
					update()
				})
				if noInput {
					pw.Disabled(true)
				}
				if !showPassword {
					pw.Password()
				}
				// 强度圆环（无密码时用相同尺寸的占位框保持等宽）
				if password != "" && mode != "decrypt" {
					_, frac, col := evaluatePasswordStrength(password)
					strengthRing(c, frac, col)
				} else {
					ui.Box(c).Size(20, 20)
				}
			})

			// 确认密码（仅加密模式）
			if mode != "decrypt" {
				ui.Row(c).Gap(6).Children(func() {
					ui.Text(c, "确认密码：").Grow(1).TextColor(labelColor(t, noInput))
					if password != "" {
						ui.Button(c, "复制").Disabled(noInput).Tooltip("复制当前密码").OnClick(func() {
							writeClipboard(password)
							update()
						})
					}
				})
				ui.Row(c).Gap(6).Children(func() {
					cp := ui.TextInput(c, &cpassword).Grow(1).OnChange(func() {
						cleaned := sanitizePassword(cpassword)
						if cleaned != cpassword {
							cpassword = cleaned
						}
						update()
					})
					if noInput {
						cp.Disabled(true)
					}
					if !showPassword {
						cp.Password()
					}
					// 匹配一致性指示环（无输入时同样保留 20px 占位）
					if password != "" && cpassword != "" {
						strengthRing(c, 1, func() ui.Color {
							if cpassword == password {
								return ui.RGBA(0x28, 0xa7, 0x45, 1) // 匹配成功绿色
							}
							return ui.RGBA(0xd9, 0x53, 0x4f, 1) // 不匹配红色
						}())
					} else {
						ui.Box(c).Size(20, 20)
					}
				})
			}

			// 密钥文件
			if !(mode == "decrypt" && !keyfile && !deniability) {
				ui.Row(c).Gap(6).Children(func() {
					ui.Text(c, "密钥文件：")
					ui.Button(c, "编辑").Tooltip("管理用于" + func() string {
						if mode != "decrypt" {
							return "加密"
						}
						return "解密"
					}()).OnClick(func() {
						showKeyfile = true
						update()
					})
					ui.Button(c, "创建").Disabled(mode == "decrypt").Tooltip("生成一个密码学安全的密钥文件").OnClick(createKeyfile)
					ui.Text(c, keyfileLabel).TextColor(t.TextMuted)
				})
			}

			ui.Divider(c)

			// 备注
			commentsDisabledNow := mode != "decrypt" && advancedDisabled || deniability
			ui.Text(c, commentsLabel).TextColor(labelColor(t, commentsDisabledNow))
			cmt := ui.TextInput(c, &comments).Grow(1)
			if commentsDisabledNow {
				cmt.Disabled(true)
			}
			if commentsDisabled {
				cmt.ReadOnly(true)
			} else if deniability {
				comments = ""
			}
			if !commentsDisabled && !commentsDisabledNow {
				cmt.Tooltip("注意：备注不会被加密！")
			}

			// 高级选项
			ui.Text(c, "高级选项：").TextColor(labelColor(t, advancedDisabled))
			if mode != "decrypt" {
				// 加密侧：双列网格横向间距加大
				ui.Row(c).Gap(24).Children(func() {
					ui.Box(c).Grow(1).Children(func() {
						ui.Checkbox(c, &paranoid, "偏执模式").Disabled(advancedDisabled).Tooltip("启用更严苛的 Argon2id 密钥派生参数（1GiB 内存/8轮迭代/8线程），极大提高抗暴力破解强度")
					})
					ui.Box(c).Grow(1).Children(func() {
						ui.Checkbox(c, &compress, "压缩文件").Disabled(advancedDisabled || recursively || !(len(allFiles) > 1 || len(onlyFolders) > 0)).Tooltip("加密前用 Deflate 压缩文件")
					})
				})
				ui.Row(c).Gap(24).Children(func() {
					ui.Box(c).Grow(1).Children(func() {
						ui.Checkbox(c, &reedsolo, "RS 纠错码").Disabled(advancedDisabled).Tooltip("启用 Reed-Solomon 矩阵纠错（20% 冗余保护），精准定位损坏并自动恢复文件")
					})
					ui.Box(c).Grow(1).Children(func() {
						ui.Checkbox(c, &delete_, "删除文件").Disabled(advancedDisabled).Tooltip("加密后删除输入文件")
					})
				})
				ui.Row(c).Gap(24).Children(func() {
					ui.Box(c).Grow(1).Children(func() {
						ui.Checkbox(c, &deniability, "隐匿加密").Disabled(advancedDisabled).Tooltip("隐匿加密/合理可否认性（Plausible Deniability）：移除文件头魔数与元数据，使密文与纯随机噪声完全一致，防止被审查者发现是加密卷。注意：解密时需手动输入相同参数")
					})
					ui.Box(c).Grow(1).Children(func() {
						ui.Checkbox(c, &recursively, "递归").Disabled(advancedDisabled || !(len(allFiles) > 1 || len(onlyFolders) > 0)).OnChange(func() {
							compress = false
						}).Tooltip("警告：仅在你知道它的作用时才使用！")
					})
				})
				ui.Row(c).Gap(8).Children(func() {
					ui.Checkbox(c, &split, "分块：").Disabled(advancedDisabled).Tooltip("将输出文件分割成更小的分块")
					sizeInput := ui.TextInput(c, &splitSize).Grow(1).OnChange(func() {
						split = splitSize != ""
					})
					sizeInput.Tooltip("输入分块大小（如 100）")
					if advancedDisabled {
						sizeInput.Disabled(true)
					}
					unitSel := ui.Select(c, &splitUnitStr, splitUnits).Width(46).OnChange(func() {
						splitSelected = indexOf(splitUnitStr, splitUnits)
					})
					unitSel.Tooltip("选择分块单位")
					if advancedDisabled {
						unitSel.Disabled(true)
					}
				})
			} else {
				// 解密侧：双列网格横向间距加大
				ui.Row(c).Gap(24).Children(func() {
					ui.Box(c).Grow(1).Children(func() {
						ui.Checkbox(c, &keep, "强制解密").Disabled(advancedDisabled || deniability).Tooltip("解密时绕过安全措施")
					})
					ui.Box(c).Grow(1).Children(func() {
						ui.Checkbox(c, &delete_, "删除卷").Disabled(advancedDisabled).Tooltip("解密成功后删除该卷")
					})
				})
				ui.Row(c).Gap(24).Children(func() {
					ui.Box(c).Grow(1).Children(func() {
						isZipVolume := strings.HasSuffix(inputFile, ".zip"+VolumeExt) || strings.HasSuffix(inputFile, ".zip.pcv")
						unzipCb := ui.Checkbox(c, &autoUnzip, "自动解压").Disabled(advancedDisabled || !isZipVolume).OnChange(func() {
							if !autoUnzip {
								sameLevel = false
							}
						})
						unzipCb.Tooltip("解密后自动解压 .zip（可能覆盖文件）")
					})
					ui.Box(c).Grow(1).Children(func() {
						levelCb := ui.Checkbox(c, &sameLevel, "同级目录").Disabled(advancedDisabled || !autoUnzip)
						levelCb.Tooltip("将 .zip 内容解压到与卷相同的文件夹")
					})
				})
			}

			// 保存输出
			if !recursively {
				ui.Row(c).Gap(6).Children(func() {
					ui.Text(c, "保存输出为：").TextColor(labelColor(t, advancedDisabled))
					ui.Text(c, outLabel()).Grow(1).TextColor(t.TextMuted)
					ui.Button(c, "更改").Disabled(advancedDisabled).Tooltip("用自定义名称和路径保存输出").OnClick(chooseOutput)
				})
			}

			ui.Divider(c)

			// 开始按钮
			ui.Button(c, startButtonLabel()).Height(34).OnClick(onClickStartButton)
		})

		// 底部独立状态栏（常驻底部，不占用内容滚动高度）
		ui.Divider(c)
		ui.Row(c).Padding(6, 12).Gap(8).Background(t.Surface).Children(func() {
			statusText := mainStatus
			statusColor := mainStatusColor
			if mainStatus == "就绪" {
				statusColor = t.TextMuted
				if requiredFreeSpace > 0 {
					multiplier := 1
					for _, cond := range []bool{len(allFiles) > 1 || len(onlyFolders) > 0, deniability, split, recombine, autoUnzip} {
						if cond {
							multiplier++
						}
					}
					statusText = "就绪（需可用空间 > " + sizeify(requiredFreeSpace*int64(multiplier)) + "）"
				}
			}
			// 状态小圆点
			ui.Box(c).Size(8, 8).Radius(4).Background(statusColor)
			ui.Text(c, statusText).TextColor(statusColor).Grow(1).Wrap()
		})
	})

	// 处理拖放（整窗区域）
	if drop, ok := ui.DropData(root, dropOpts); ok {
		if files, err := drop.Data.Files(); err == nil && len(files) > 0 {
			onDrop(files)
		}
	}
}
