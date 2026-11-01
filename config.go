package main

import (
	"time"

	"github.com/egoist/mygo/ui"
)

// ==========================================
// 系统版本与常量配置
// ==========================================

const (
	AppVersion = "v1.0.1"
	AppName    = "CipherBox"
	VolumeExt  = ".sbx" // 加密卷文件扩展名
	MagicSBX1  = "SBX1" // 密文卷魔数标识 (CipherBox v1)

	// 存储单位常量
	KiB = 1 << 10
	MiB = 1 << 20
	GiB = 1 << 30
	TiB = 1 << 40

	// 窗口布局默认尺寸
	WindowWidth     = 360
	WindowHeight    = 620
	WindowMinWidth  = 340
	WindowMinHeight = 620
)

// UI 状态提示色 (mygo: RGB 0-255 uint8)
var (
	WHITE       = ui.RGBA(255, 255, 255, 1)
	RED         = ui.RGBA(255, 0, 0, 1)
	GREEN       = ui.RGBA(0, 255, 0, 1)
	YELLOW      = ui.RGBA(255, 255, 0, 1)
	TRANSPARENT = ui.RGBA(0, 0, 0, 0)
)

// ==========================================
// 业务与 UI 全局状态配置
// ==========================================

// 核心工作状态
var (
	mode     string // "encrypt" 或 "decrypt"
	working  bool   // 是否正在执行加解密工作
	scanning bool   // 是否正在扫描拖入的文件夹
)

// 弹窗状态
var (
	showPassgen   bool // 密码生成弹窗
	showKeyfile   bool // 密钥文件管理弹窗
	showOverwrite bool // 同名文件覆盖确认弹窗
	showProgress  bool // 任务进度弹窗
)

// 输入与输出文件状态
var (
	inputFile   string
	inputFileOld string
	outputFile  string
	onlyFiles   []string
	onlyFolders []string
	allFiles    []string
	inputLabel  = "将文件或文件夹拖入此窗口"
)

// 密码与安全状态
var (
	password           string
	cpassword          string
	passwordStrength   int
	passwordStateLabel = "显示"
)

// 密码生成器配置
var (
	passgenLength  float64 = 10
	passgenUpper   bool
	passgenLower   bool
	passgenNums    bool
	passgenSymbols bool
	passgenCopy    bool
)

// 密钥文件配置
var (
	keyfile        bool
	keyfiles       []string
	keyfileOrdered bool
	keyfileLabel   = "未选择"
)

// 备注信息
var (
	comments         string
	commentsLabel    = "备注："
	commentsDisabled bool
)

// 高级加密与解密选项
var (
	paranoid      bool     // 偏执模式 (Argon2id 严苛参数)
	reedsolo      bool     // Reed-Solomon 纠错码冗余
	deniability   bool     // 隐匿加密 / 合理可否认性
	recursively   bool     // 递归批量处理
	split         bool     // 分块输出
	splitSize     string   // 分块大小输入值
	splitUnits    = []string{"KiB", "MiB", "GiB", "TiB", "总计"}
	splitSelected int32    = 1 // 默认选中 "MiB"
	recombine     bool     // 是否重组成完整卷
	compress      bool     // Deflate 压缩
	delete_       bool     // 操作完成后删除源文件
	autoUnzip     bool     // 解密后自动解压 .zip
	sameLevel     bool     // 解压至同级目录
	keep          bool     // 强制解密（忽略校验错误）
	kept          bool     // 是否保留了损坏解密文件
)

// 任务运行与进度统计
var (
	startLabel        = "开始"
	mainStatus        = "就绪"
	mainStatusColor   = WHITE
	popupStatus       string
	requiredFreeSpace int64

	progress     float32
	progressInfo string
	speed        float64
	eta          string
	canCancel    bool

	compressDone  int64
	compressTotal int64
	compressStart time.Time
)
