# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
from burp import IParameter, IRequestInfo, IHttpRequestResponse
from java.awt import (BorderLayout, Dimension, FlowLayout, GridLayout, 
                     Toolkit, Color, Font, Insets)
from java.awt.datatransfer import StringSelection
from javax.swing import (JPanel, JButton, JTextArea, JScrollPane, JList,
                         DefaultListModel, JLabel, JTextField, JPopupMenu, 
                         JMenuItem, JSeparator, JCheckBox, JComboBox, 
                         BorderFactory)
from java.awt.event import MouseAdapter, MouseEvent
from javax.swing import SwingUtilities
from java.io import PrintWriter
from java.util.concurrent import ThreadPoolExecutor, LinkedBlockingQueue, TimeUnit
from java.net import URL
import re
import hashlib

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    # 常量定义
    EXCLUDED_EXTENSIONS = set([
        ".3g2", ".smo",".3gp", ".7z", ".aac", ".abw", ".aif", ".aifc", ".aiff",
        ".arc", ".au",".umo",".avi", ".azw", ".bin", ".bmp", ".bz", ".bz2",
        ".cmx", ".cod", ".csh",".nmo",".css", ".csv", ".doc", ".docx", ".eot",
        ".epub", ".gif", ".gz", ".ico",".dmo",".ics", ".ief", ".jar", ".jfif",
        ".jpe", ".jpeg", ".jpg", ".m3u", ".mid", ".amo",".midi", ".mjs", ".mp2",
        ".mp3", ".mpa", ".mpe", ".mpeg", ".mpg", ".mpkg",".ymo", ".mpp", ".mpv2",
        ".odp", ".ods", ".odt", ".oga", ".ogv", ".ogx", ".otf", ".pbm",
        ".pdf", ".pgm", ".png", ".pnm", ".ppm", ".ppt", ".pptx", ".ra",
        ".ram", ".rar", ".ras", ".rgb", ".rmi", ".rtf", ".snd", ".svg",
        ".swf", ".tar", ".tif", ".tiff", ".ttf", ".vsd", ".wav", ".weba",
        ".webm", ".webp", ".woff", ".woff2", ".xbm", ".xls", ".xlsx",
        ".xpm", ".xul", ".xwd", ".zip", ".js"
    ])
    
    PAYLOAD_HTML = "<h1>sunday0w0</h1>"
    PAYLOAD_HTML_ENCODED = "%3Ch1%3Esunday0w0%3C%2Fh1%3E"
    PAYLOAD_ALTERNATIVE = "sundayY0w0Y"
    
    def __init__(self):
        self._isEnabled = True
        self.whitelist = None
        self.COLOR_DANGER = Color(255, 0, 0)
        self.whitelist_pattern = None
        self.seen = set()  # 存储已扫描的参数组合哈希
        self.scan_history = {}  # 存储哈希到原始URL的映射
        self._requestMap = {}
        self._responseMap = {}
        
        # 颜色方案
        self.COLOR_PRIMARY = Color(66, 133, 244)  # 蓝色
        self.COLOR_SUCCESS = Color(52, 168, 83)   # 绿色
        self.COLOR_DANGER = Color(255, 0, 0)      # 强化红色
        self.COLOR_WARNING = Color(251, 188, 5)   # 黄色
        self.COLOR_INFO = Color(128, 0, 128)      # 紫色(信息)
        self.COLOR_LIGHT = Color(241, 243, 244)   # 浅灰
        self.COLOR_DARK = Color(50, 50, 50)       # 深灰
        
        # 字体设置 - 使用支持中文的字体
        self.FONT_TITLE = Font("Microsoft YaHei", Font.BOLD, 14)
        self.FONT_LABEL = Font("Microsoft YaHei", Font.PLAIN, 12)
        self.FONT_BOLD = Font("Microsoft YaHei", Font.BOLD, 12)
        self.FONT_MONOSPACED = Font("Monospaced", Font.PLAIN, 12)
        
        # 初始化列表组件
        self.model1 = DefaultListModel()
        self.model2 = DefaultListModel()
        self.list1 = JList(self.model1)
        self.list2 = JList(self.model2)
        
        # 初始化文本区域
        from javax.swing import JEditorPane
        self.req_area = JEditorPane("text/html", "")
        self.res_area = JEditorPane("text/html", "")
        self.req_area.setEditable(False)
        self.res_area.setEditable(False)

        # 新增高亮标记字符串
        self.PAYLOAD_MARKER = "<!-- PAYLOAD_POSITION -->"
        self.DETECTION_MARKER = "<!-- DETECTION_POSITION -->"
        
        # 线程池配置 - 优化
        core_pool_size = 10
        max_pool_size = 20
        keep_alive_time = 30
        queue_capacity = 100
        
        self.executor = ThreadPoolExecutor(
            core_pool_size, 
            max_pool_size, 
            keep_alive_time, 
            TimeUnit.SECONDS,
            LinkedBlockingQueue(queue_capacity)
        )
        
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.setExtensionName("XSS-scan")

        # 构建美化后的UI
        self._panel = JPanel(BorderLayout())
        self._panel.setBackground(self.COLOR_LIGHT)
        self.stdout.println("[+]This program is for internal use only and must not be disseminated[+]\n")
        self.stdout.println("[+]The copyright belongs to Hacker Kid[+]\n")
        self.stdout.println("[+]Paid secondary selling is prohibited.[+]\n")
        self.stdout.println("[+]Original author WX: SunDay2__[+]\n")
        
        # 顶部控制区
        topPanel = self._createTopPanel()
        self._panel.add(topPanel, BorderLayout.NORTH)
        
        # 中间和底部区域 - 使用2x2网格布局
        centerBottomPanel = self._createCenterBottomPanel()
        self._panel.add(centerBottomPanel, BorderLayout.CENTER)

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        
    def _createTopPanel(self):
        topPanel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 10))
        topPanel.setBackground(self.COLOR_LIGHT)
        
        # 开关按钮
        self.toggle_btn = JButton("ON", actionPerformed=self._toggle)
        self.toggle_btn.setPreferredSize(Dimension(80, 30))
        self.toggle_btn.setFont(self.FONT_BOLD)
        self.toggle_btn.setForeground(Color.WHITE)
        self.toggle_btn.setBackground(self.COLOR_SUCCESS)
        self._applyButtonStyle(self.toggle_btn, is_toggle=True)  # 指定为切换按钮
        topPanel.add(self.toggle_btn)
        
        # 清除按钮
        clear_btn = JButton("Clear", actionPerformed=self._clear)
        clear_btn.setPreferredSize(Dimension(80, 30))
        clear_btn.setFont(self.FONT_BOLD)
        clear_btn.setForeground(self.COLOR_DARK)  # 文字设为深色
        clear_btn.setBackground(Color.WHITE)      # 背景设为白色
        self._applyButtonStyle(clear_btn)  # 普通按钮
        topPanel.add(clear_btn)
        
        # 添加分隔线
        topPanel.add(self._createSeparator(10, 30))
        
        # 白名单设置
        whitelistLabel = JLabel("Whitelist :")
        whitelistLabel.setFont(self.FONT_LABEL)
        topPanel.add(whitelistLabel)
        
        self.whitelist_field = JTextField(20)
        self.whitelist_field.setPreferredSize(Dimension(200, 30))
        self.whitelist_field.setFont(self.FONT_LABEL)
        self._applyTextFieldStyle(self.whitelist_field)
        topPanel.add(self.whitelist_field)
        
        apply_btn = JButton("Application", actionPerformed=self._apply_whitelist)
        apply_btn.setPreferredSize(Dimension(80, 30))
        apply_btn.setFont(self.FONT_BOLD)
        apply_btn.setForeground(self.COLOR_DARK)  # 文字设为深色
        apply_btn.setBackground(Color.WHITE)      # 背景设为白色
        self._applyButtonStyle(apply_btn)  # 普通按钮
        topPanel.add(apply_btn)
        
        # 添加分隔线
        topPanel.add(self._createSeparator(10, 30))
        
        # 线程设置
        threadsLabel = JLabel("ThreadCount:")
        threadsLabel.setFont(self.FONT_LABEL)
        topPanel.add(threadsLabel)
        
        self.thread_field = JTextField("10", 5)
        self.thread_field.setPreferredSize(Dimension(50, 30))
        self.thread_field.setFont(self.FONT_LABEL)
        self._applyTextFieldStyle(self.thread_field)
        topPanel.add(self.thread_field)
        
        run_btn = JButton("Run", actionPerformed=self._set_threads)
        run_btn.setPreferredSize(Dimension(80, 30))
        run_btn.setFont(self.FONT_BOLD)
        run_btn.setForeground(self.COLOR_DARK)  # 文字设为深色
        run_btn.setBackground(Color.WHITE)      # 背景设为白色
        self._applyButtonStyle(run_btn)  # 普通按钮
        topPanel.add(run_btn)
        
        authorLabel = JLabel("Original author WX: SunDay2__")
        authorLabel.setFont(Font("Microsoft YaHei", Font.ITALIC, 11))
        authorLabel.setForeground(self.COLOR_DARK)
        topPanel.add(authorLabel)
        
        return topPanel
        
    def _createCenterBottomPanel(self):
        # 使用2行2列的网格布局，让四个面板平分空间
        panel = JPanel(GridLayout(2, 2, 10, 10))
        panel.setBackground(self.COLOR_LIGHT)
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # URL列表1（左上）
        list1Panel = self._createListPanel("URLlist1", self.COLOR_PRIMARY, self.list1, self.model1, 1)
        panel.add(list1Panel)
        
        # URL列表2（右上）
        list2Panel = self._createListPanel("URLlist2", self.COLOR_INFO, self.list2, self.model2, 2)
        panel.add(list2Panel)
        
        # 请求详情（左下）
        reqPanel = self._createTextPanel("Request details", self.COLOR_DARK, self.req_area)
        panel.add(reqPanel)
        
        # 响应详情（右下）
        resPanel = self._createTextPanel("Response details", self.COLOR_DARK, self.res_area)
        panel.add(resPanel)
        
        return panel
    
    def _createListPanel(self, title, color, list_obj, model, list_idx):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(color, 1), 
            title, 
            0, 0, self.FONT_TITLE, color
        ))
        
        list_obj.setFont(self.FONT_MONOSPACED)
        list_obj.setSelectionBackground(color.brighter())
        list_obj.setSelectionForeground(Color.WHITE)
        list_obj.setFixedCellHeight(20)
        list_obj.addMouseListener(SingleSelectMouseListener(self, list_idx))
        
        scrollPane = JScrollPane(list_obj)
        scrollPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        panel.add(scrollPane, BorderLayout.CENTER)
        
        return panel
    
    def _createTextPanel(self, title, color, text_area):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(color, 1), 
            title, 
            0, 0, self.FONT_TITLE, color
        ))
        
        # 为JEditorPane设置样式
        text_area.setFont(self.FONT_MONOSPACED)
        text_area.setEditable(False)
        self._add_context(text_area)
        
        scrollPane = JScrollPane(text_area)
        scrollPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        panel.add(scrollPane, BorderLayout.CENTER)
        
        return panel
    
    def _createSeparator(self, width, height):
        separator = JPanel()
        separator.setPreferredSize(Dimension(width, height))
        separator.setBackground(self.COLOR_LIGHT)
        return separator
    
    def _applyButtonStyle(self, button, is_toggle=False):
        button.setFocusPainted(False)
        button.setMargin(Insets(5, 10, 5, 10))
        button.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY, 1),
            BorderFactory.createEmptyBorder(5, 5, 5, 10)
        ))
        
        if is_toggle:
            # 切换按钮使用专门的监听器，颜色由状态控制
            button.addMouseListener(ToggleButtonHoverListener(self, button))
        else:
            # 普通按钮使用原有的监听器，保持原有颜色
            button.addMouseListener(RegularButtonHoverListener(button))
    
    def _applyTextFieldStyle(self, textField):
        textField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY, 1),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ))
        
    def getTabCaption(self):
        return "XSS-Scan"

    def getUiComponent(self):
        return self._panel

    # --- UI callbacks ---
    def _toggle(self, event):
        self._isEnabled = not self._isEnabled
        self.toggle_btn.setText("ON" if self._isEnabled else "OFF")
        if self._isEnabled:
            self.toggle_btn.setBackground(self.COLOR_SUCCESS)  # 绿色（ON状态）
        else:
            self.toggle_btn.setBackground(self.COLOR_DANGER)  # 红色（OFF状态）
        
    def _clear(self, event):
        self.model1.clear()
        self.model2.clear()
        self.req_area.setText("")
        self.res_area.setText("")
        self.seen.clear()
        self.scan_history.clear()
        self._requestMap.clear()
        self._responseMap.clear()

    def _apply_whitelist(self, event):
        whitelist_text = self.whitelist_field.getText().strip()
        if not whitelist_text:
            self.whitelist = None
            self.whitelist_pattern = None
            self.stdout.println("White list cleared")
            return
            
        self.whitelist = whitelist_text
        
        # 编译正则表达式
        try:
            # 支持简单的通配符转换
            if not whitelist_text.startswith('^'):
                whitelist_text = '^' + whitelist_text
            if not whitelist_text.endswith('$'):
                whitelist_text = whitelist_text + '$'
                
            # 将 * 转换为 .*
            whitelist_text = whitelist_text.replace('*', '.*')
            
            self.whitelist_pattern = re.compile(whitelist_text)
            self.stdout.println("White list updated: " + str(self.whitelist))
        except Exception as e:
            self.stdout.println("Invalid white list pattern: " + str(e))
            self.whitelist_pattern = None

    def _set_threads(self, event):
        try:
            n = int(self.thread_field.getText().strip())
            if n < 1 or n > 100:
                raise ValueError("Thread count must be between 1 and 100")
                
            # 优雅关闭现有线程池
            self.executor.shutdown()
            if not self.executor.awaitTermination(5, TimeUnit.SECONDS):
                self.executor.shutdownNow()
                
            # 创建新线程池
            self.executor = ThreadPoolExecutor(
                n, n, 30, TimeUnit.SECONDS,
                LinkedBlockingQueue(100)
            )
            self.stdout.println("Thread count updated: " + str(n))
        except Exception as e:
            self.stdout.println("Invalid thread count: " + str(e))

    def _add_context(self, area):
        menu = JPopupMenu()
        item = JMenuItem("Copy", actionPerformed=lambda e: self._copy(area))
        item.setFont(self.FONT_LABEL)
        menu.add(item)
        area.addMouseListener(ContextMenu(menu))

    def _copy(self, area):
        # 处理JEditorPane的内容复制
        if isinstance(area, JEditorPane):
            sel = StringSelection(area.getText())
        else:
            sel = StringSelection(area.getText())
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, None)
        
    # --- 新增高亮处理函数 ---
    def _highlight_payload(self, content, payload, marker):
        """使用鲜红色背景区块标注payload位置"""
        # 转义HTML特殊字符，防止干扰现有HTML结构
        safe_content = content.replace("<", "&lt;").replace(">", "&gt;")
        safe_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
        
        # 使用<span>标签和CSS设置鲜红色背景，添加边框以增强可见性
        highlighted = safe_content.replace(safe_payload, 
            """<span style="background-color: #FFCCCC; 
                          border: 1px solid #FF0000; 
                          padding: 0 2px; 
                          display: inline-block;
                          font-weight: bold;
                          color: #CC0000;">%s</span>%s""" % (safe_payload, marker))
        
        # 使用<pre>标签保持原始格式，添加基本样式
        return """<html>
                  <body style="font-family: monospace; font-size: 12px; line-height: 1.5;">
                  <pre>%s</pre>
                  </body>
                  </html>""" % highlighted
    
    def _process_highlight(self, req_str, resp_body, payload):
        """统一处理请求和响应的高亮显示"""
        # 标注请求中的Payload位置
        req_highlight = self._highlight_payload(req_str, payload, self.PAYLOAD_MARKER)
        
        # 标注响应中的检测位置
        resp_highlight = self._highlight_payload(resp_body, payload, self.DETECTION_MARKER)
        return req_highlight, resp_highlight

    # --- HTTP listener ---
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._isEnabled or not messageIsRequest or toolFlag != self._callbacks.TOOL_PROXY:
            return

        try:
            svc = messageInfo.getHttpService()
            host = svc.getHost()
            if not self._domain_allowed(host):
                return

            req = messageInfo.getRequest()
            info = self._helpers.analyzeRequest(svc, req)
            url = info.getUrl().toString()
            
            # 使用改进的哈希生成方法，只考虑路径和参数名
            url_hash = self._get_url_hash(url)
            
            # 检查是否已扫描过相同参数组合
            if url_hash in self.seen:
                return  # 已存在记录，直接跳过测试
                
            # 记录完整URL，用于UI显示
            self.scan_history[url_hash] = url
            self.seen.add(url_hash)  # 标记为已处理

            path = info.getUrl().getPath().lower()
            for ext in self.EXCLUDED_EXTENSIONS:
                if path.endswith(ext):
                    return

            # 提交扫描任务
            self.executor.submit(lambda: self._scan(svc, req, url_hash))
        except Exception as e:
            self.stdout.println("Error processing HTTP message: " + str(e))

    def _domain_allowed(self, host):
        if not self.whitelist or self.whitelist == "*":
            return True
            
        if self.whitelist_pattern:
            return self.whitelist_pattern.match(host) is not None
            
        # 回退到原始逻辑
        if self.whitelist.startswith("*."):
            return host.endswith(self.whitelist[1:])
        return host == self.whitelist

    def _scan(self, svc, orig_req, url_hash):
        try:
            info = self._helpers.analyzeRequest(svc, orig_req)
            params = info.getParameters()
            base = svc.getHost() + info.getUrl().getPath()

            for p in params:
                # 使用新的HTML Payload
                p1 = self._helpers.buildParameter(
                    p.getName(),
                    self.PAYLOAD_HTML_ENCODED,
                    p.getType()
                )
                req1 = self._helpers.updateParameter(orig_req, p1)
                resp1 = self._callbacks.makeHttpRequest(svc, req1)
                
                # 强制使用UTF-8解码响应
                body1_bytes = resp1.getResponse()
                body1 = self._helpers.bytesToString(body1_bytes)
                
                # 检查响应中是否存在原始HTML标签
                if self.PAYLOAD_HTML in body1:
                    SwingUtilities.invokeLater(lambda:
                        self._add_result(1, url_hash, req1, body1)
                    )
                    return

                # 保留第二个Payload作为备用检测
                payload2 = self.PAYLOAD_ALTERNATIVE
                p2 = self._helpers.buildParameter(
                    p.getName(),
                    payload2,
                    p.getType()
                )
                req2 = self._helpers.updateParameter(orig_req, p2)
                resp2 = self._callbacks.makeHttpRequest(svc, req2)
                
                # 强制使用UTF-8解码响应
                body2_bytes = resp2.getResponse()
                body2 = self._helpers.bytesToString(body2_bytes)
                
                if payload2 in body2:
                    SwingUtilities.invokeLater(lambda:
                        self._add_result(2, url_hash, req2, body2)
                    )
                    return
        except Exception as e:
            # 修改此处，使用传统字符串格式化替代f-string
            self.stdout.println("Scan error for %s: %s" % (url_hash, str(e)))
                
    def _add_result(self, list_no, url_hash, req, resp_body):
        try:
            # 从历史记录中获取原始URL用于显示
            original_url = self.scan_history.get(url_hash, url_hash)
            
            # 优化URL显示 - 截断长路径
            try:
                parsed_url = URL(original_url)
                path = parsed_url.getPath()
                query = parsed_url.getQuery()
                
                # 截断路径长度（保留前80个字符）
                truncated_path = path[:80] + ('...' if len(path) > 80 else '')
                
                # 重建URL（仅显示域名和截断后的路径）
                truncated_url = "%s://%s%s" % (parsed_url.getProtocol(), parsed_url.getHost(), truncated_path)
                if query:
                    truncated_url += "?" + query[:40] + ('...' if len(query) > 40 else '')
            except:
                # 异常处理：直接使用原始URL
                truncated_url = original_url[:120] + ('...' if len(original_url) > 120 else '')
            
            # 添加到列表
            model = self.model1 if list_no == 1 else self.model2
            model.addElement(truncated_url)
            
            # 存储完整请求/响应
            req_str = self._helpers.bytesToString(req)
            resp_str = resp_body
            
            # 分别处理请求和响应的高亮
            payload_found = False
            
            # 处理请求中的编码 Payload
            if self.PAYLOAD_HTML_ENCODED in req_str:
                # 高亮请求中的编码 Payload
                req_highlight = self._highlight_payload(req_str, self.PAYLOAD_HTML_ENCODED, self.PAYLOAD_MARKER)
                # 高亮响应中的原始 HTML
                resp_highlight = self._highlight_payload(resp_str, self.PAYLOAD_HTML, self.DETECTION_MARKER)
                payload_found = True
            
            # 处理第二个 Payload
            elif self.PAYLOAD_ALTERNATIVE in req_str:
                req_highlight, resp_highlight = self._process_highlight(req_str, resp_str, self.PAYLOAD_ALTERNATIVE)
                payload_found = True
            
            # 如果未找到任何 Payload，使用原始内容
            if not payload_found:
                req_highlight = """<html>
                                  <body style="font-family: monospace; font-size: 12px; line-height: 1.5;">
                                  <pre>%s</pre>
                                  </body>
                                  </html>""" % req_str.replace("<", "&lt;").replace(">", "&gt;")
                
                resp_highlight = """<html>
                                   <body style="font-family: monospace; font-size: 12px; line-height: 1.5;">
                                   <pre>%s</pre>
                                   </body>
                                   </html>""" % resp_str.replace("<", "&lt;").replace(">", "&gt;")
            
            # 存储带高亮的内容
            self._requestMap[truncated_url] = req_highlight
            self._responseMap[truncated_url] = resp_highlight
            
            # 如果是新添加的URL，自动选中并显示详情
            if model.size() == 1:
                SwingUtilities.invokeLater(lambda: {
                    self.list1.setSelectedIndex(0) if list_no == 1 else self.list2.setSelectedIndex(0),
                    self.req_area.setText(req_highlight),
                    self.res_area.setText(resp_highlight)
                })
        except Exception as e:
            self.stdout.println("Error adding result: " + str(e))
            
    def _get_url_hash(self, url):
        """生成URL的哈希值，只考虑路径和参数名，忽略参数值"""
        try:
            parsed_url = URL(url)
            path = parsed_url.getPath()
            query = parsed_url.getQuery()
            
            # 处理路径部分
            path_hash = hashlib.md5(path.encode('utf-8')).hexdigest()
            
            # 处理查询参数部分
            param_hash = ""
            if query:
                # 解析查询参数，只保留参数名
                params = {}
                for param in query.split('&'):
                    if '=' in param:
                        name, value = param.split('=', 1)
                        params[name] = None  # 忽略值，只保留参数名
                    else:
                        params[param] = None  # 处理没有值的参数
                        
                # 按参数名排序后生成字符串
                sorted_params = sorted(params.keys())
                param_str = '&'.join(sorted_params)
                param_hash = hashlib.md5(param_str.encode('utf-8')).hexdigest()
            
            # 组合路径哈希和参数哈希
            combined_hash = path_hash + "_" + param_hash
            return combined_hash
        except Exception as e:
            # 异常时返回原始URL的哈希
            self.stdout.println("Error generating parameter hash: " + str(e))
            return hashlib.md5(url.encode('utf-8')).hexdigest()

class SingleSelectMouseListener(MouseAdapter):
    def __init__(self, extender, list_idx):
        self.extender = extender
        self.list_idx = list_idx

    def mouseClicked(self, event):
        # 清除另一个列表的选择
        if self.list_idx == 1:
            self.extender.list2.clearSelection()
        else:
            self.extender.list1.clearSelection()
            
        list_obj = (self.extender.list1 if self.list_idx == 1 else self.extender.list2)
        sel = list_obj.getSelectedValue()
        if sel:
            req_text = self.extender._requestMap.get(sel, "")
            resp_text = self.extender._responseMap.get(sel, "")
            self.extender.req_area.setText(req_text)
            self.extender.res_area.setText(resp_text)

class ContextMenu(MouseAdapter):
    def __init__(self, menu):
        self.menu = menu
        
    def mousePressed(self, e):
        self._show(e)
        
    def mouseReleased(self, e):
        self._show(e)
        
    def _show(self, e):
        if e.isPopupTrigger():
            self.menu.show(e.getComponent(), e.getX(), e.getY())

class ToggleButtonHoverListener(MouseAdapter):
    def __init__(self, extender, button):
        self.extender = extender
        self.button = button
        
    def mouseEntered(self, e):
        # 鼠标进入时，根据当前状态计算高亮颜色
        current_color = self.button.getBackground()
        self.button.setBackground(current_color.brighter())
        
    def mouseExited(self, e):
        # 鼠标离开时，根据当前状态设置颜色
        if self.extender._isEnabled:
            self.button.setBackground(self.extender.COLOR_SUCCESS)  # ON状态为绿色
        else:
            self.button.setBackground(self.extender.COLOR_DANGER)   # OFF状态为红色

class RegularButtonHoverListener(MouseAdapter):
    def __init__(self, button):
        self.button = button
        self.originalBackground = button.getBackground()
        
    def mouseEntered(self, e):
        # 白色按钮悬停时显示淡灰色，提高交互反馈
        self.button.setBackground(Color(240, 240, 240))
        
    def mouseExited(self, e):
        self.button.setBackground(self.originalBackground)  # 恢复白色