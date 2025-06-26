<?php
/**
 * 评论设置 hCaptcha / Turnstile / Cap 验证并通过规则过滤
 *
 * @package CaptchaPlus
 * @author ATP
 * @version 1.3.0
 * @link https://atpx.com
 * 
 * Version 1.3.0 (2025-06-27)
 * 添加 Cap 验证支持
 * 
 * Version 1.2.1 (2025-04-21)
 * 修复Content-Type问题和安全性增强
 * 
 * Version 1.2.0 (2023-01-22)
 * 添加 Cloudflare Turnstile 验证
 * 
 * Version 1.1.0 (2022-11-10)
 * 添加评论语种过滤功能
 * 
 * Version 1.0.0 (2022-11-05)
 * 使用 hCaptcha 验证
 */

if (!defined('__TYPECHO_ROOT_DIR__')) {
	exit;
}

use Typecho\Plugin\PluginInterface;
use Typecho\Widget;
use Typecho\Widget\Exception;
use Typecho\Widget\Helper\Form;
use Typecho\Widget\Helper\Form\Element\Text;
use Typecho\Widget\Helper\Form\Element\Radio;
use Typecho\Widget\Helper\Form\Element\Textarea;
use Typecho\Cookie;
use Widget\Options;

class CaptchaPlus_Plugin implements PluginInterface
{
	/**
	 * 激活插件方法,如果激活失败,直接抛出异常
	 */
	public static function activate()
	{
		\Typecho\Plugin::factory('Widget_Feedback')->comment = __CLASS__ . '::filter';
		return _t('插件已启用');
	}

	/**
	 * 禁用插件方法,如果禁用失败,直接抛出异常
	 */
	public static function deactivate()
	{
	}

	/**
	 * 获取插件配置面板
	 *
	 * @param Form $form
	 */
	public static function config(Form $form)
	{
		$captcha_choose = new Radio('captcha_choose', array("hcaptcha" => "hCaptcha", "turnstile" => "Turnstile", "cap" => "Cap"), "hcaptcha", _t('验证工具'), _t('选择使用 hCpatcha、Cloudflare Turnstile 或者 Cap 验证'));
		$form->addInput($captcha_choose);

		$site_key = new Text('site_key', NULL, '', _t('Site Key'), _t('需要注册 <a href="https://www.hcaptcha.com/" target="_blank">hCaptcha</a>、<a href="https://dash.cloudflare.com/sign-up" target="_blank">Cloudflare</a> 账号或配置 Cap Standalone 服务以获取 <b>site key</b> 和 <b>secret key</b>'));
		$form->addInput($site_key);

		$secret_key = new Text('secret_key', NULL, '', _t('Secret Key'), _t(''));
		$form->addInput($secret_key);

		$cap_endpoint = new Text('cap_endpoint', NULL, '', _t('Cap API 端点'), _t('仅当使用 Cap 验证时需要填写，格式：https://your-cap-server.com/ （注意最后的斜杠）'));
		$form->addInput($cap_endpoint);

		$cap_use_self_hosted = new Radio('cap_use_self_hosted', array("0" => "使用 CDN", "1" => "使用自托管资源"), "0", _t('Cap 资源加载'), _t('选择使用 CDN 还是自托管的 Cap 服务器资源（需要在 Cap 服务器上启用 Asset server）'));
		$form->addInput($cap_use_self_hosted);

		$widget_theme = new Radio('widget_theme', array("light" => "浅色", "dark" => "深色"), "light", _t('主题'), _t('设置验证工具主题颜色，默认为浅色'));
		$form->addInput($widget_theme);

		$widget_size = new Radio('widget_size', array("normal" => "常规", "compact" => "紧凑"), "normal", _t('样式'), _t('设置验证工具布局样式，默认为常规'));
		$form->addInput($widget_size);

		$opt_noru = new Radio(
			'opt_noru',
			array("none" => "无动作", "waiting" => "标记为待审核", "spam" => "标记为垃圾", "abandon" => "评论失败"),
			"abandon",
			_t('俄文评论操作'),
			_t('如果评论中包含俄文，则强行按该操作执行')
		);
		$form->addInput($opt_noru);

		$opt_nocn = new Radio(
			'opt_nocn',
			array("none" => "无动作", "waiting" => "标记为待审核", "spam" => "标记为垃圾", "abandon" => "评论失败"),
			"waiting",
			_t('非中文评论操作'),
			_t('如果评论中不包含中文，则强行按该操作执行')
		);
		$form->addInput($opt_nocn);

		$opt_ban = new Radio(
			'opt_ban',
			array("none" => "无动作", "waiting" => "标记为待审核", "spam" => "标记为垃圾", "abandon" => "评论失败"),
			"abandon",
			_t('禁止词汇操作'),
			_t('如果评论中包含禁止词汇列表中的词汇，将执行该操作')
		);
		$form->addInput($opt_ban);

		$words_ban = new Textarea(
			'words_ban',
			NULL,
			"fuck\n傻逼\ncnm",
			_t('禁止词汇'),
			_t('多条词汇请用换行符隔开')
		);
		$form->addInput($words_ban);

		$opt_chk = new Radio(
			'opt_chk',
			array("none" => "无动作", "waiting" => "标记为待审核", "spam" => "标记为垃圾", "abandon" => "评论失败"),
			"waiting",
			_t('敏感词汇操作'),
			_t('如果评论中包含敏感词汇列表中的词汇，将执行该操作')
		);
		$form->addInput($opt_chk);

		$words_chk = new Textarea(
			'words_chk',
			NULL,
			"http://\nhttps://",
			_t('敏感词汇'),
			_t('多条词汇请用换行符隔开<br />注意：如果词汇同时出现于禁止词汇，则执行禁止词汇操作')
		);
		$form->addInput($words_chk);
		
		$log_enable = new Radio('log_enable', array("0" => "关闭", "1" => "开启"), "1", _t('启用日志'), _t('记录验证失败和可疑评论的详细信息，便于排查问题'));
		$form->addInput($log_enable);
	}

	/**
	 * 个人用户的配置面板
	 *
	 * @param Form $form
	 */
	public static function personalConfig(Form $form)
	{
	}

	/**
	 * 显示 hCaptcha / Turnstile / Cap
	 */
	public static function output()
	{
		$filter_set = Options::alloc()->plugin('CaptchaPlus');
		$captcha_choose = $filter_set->captcha_choose;
		$site_key = $filter_set->site_key;
		$secret_key = $filter_set->secret_key;
		$cap_endpoint = $filter_set->cap_endpoint;
		$cap_use_self_hosted = $filter_set->cap_use_self_hosted;
		$widget_theme = $filter_set->widget_theme;
		$widget_size = $filter_set->widget_size;
		$script = "";
		if ($site_key != "" && $secret_key != "") {
			if ($captcha_choose == "hcaptcha") {
				$script = '<script src="https://hcaptcha.com/1/api.js" async defer></script><div class="h-captcha" data-sitekey="' . $site_key . '" data-theme="' . $widget_theme . '" data-size="' . $widget_size . '"></div>';
			} elseif ($captcha_choose == "turnstile") {
				$script = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script><div class="cf-turnstile" data-sitekey="' . $site_key . '" data-theme="' . $widget_theme . '" data-size="' . $widget_size . '"></div>';
			} else {
				// Cap 验证
				if (!empty($cap_endpoint)) {
					$cap_api_endpoint = rtrim($cap_endpoint, '/') . '/' . $site_key . '/';
					
					// 根据配置选择资源加载方式
					if ($cap_use_self_hosted == "1") {
						// 使用自托管资源
						$widget_script_url = rtrim($cap_endpoint, '/') . '/assets/widget.js';
						$script = '<script src="' . $widget_script_url . '" async defer></script>';
					} else {
						// 使用 CDN 资源
						$script = '<script src="https://cdn.jsdelivr.net/npm/@cap.js/widget" async defer></script>';
					}
					
					$script .= '<cap-widget data-cap-api-endpoint="' . $cap_api_endpoint . '" data-cap-hidden-field-name="cap-token"></cap-widget>';
				} else {
					echo '<div style="color:red;margin:10px 0;">Cap API 端点未配置，请联系站长</div>';
					return;
				}
			}
			echo $script;
		} else {
			echo '<div style="color:red;margin:10px 0;">验证码未配置，请联系站长</div>';
		}
	}
	
	/**
	 * 记录日志
	 * 
	 * @param string $message 日志信息
	 * @param string $type 日志类型
	 */
	private static function log($message, $type = 'info')
	{
	    $filter_set = Options::alloc()->plugin('CaptchaPlus');
	    if (empty($filter_set->log_enable) || $filter_set->log_enable != '1') {
	        return;
	    }
	    
	    $log_file = __TYPECHO_ROOT_DIR__ . '/usr/plugins/CaptchaPlus/captcha.log';
	    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
	    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'unknown';
	    
	    $log_message = date('[Y-m-d H:i:s]') . " [{$type}] [{$ip}] {$message} | UA: {$ua}\n";
	    
	    @error_log($log_message, 3, $log_file);
	}

	/**
	 * 插件实现方法
	 *
	 * @access public
	 */
	public static function filter($comment)
	{
		$filter_set = Options::alloc()->plugin('CaptchaPlus');
		$user = Widget::widget('Widget_User');
		$captcha_choose = $filter_set->captcha_choose;
		$secret_key = $filter_set->secret_key;
		$cap_endpoint = $filter_set->cap_endpoint;
		
		// 管理员跳过验证
		if ($user->hasLogin() && $user->pass('administrator', true)) {
			return $comment;
		}
		
		// 确定验证服务和token
		if ($captcha_choose == "hcaptcha") {
			$post_token = isset($_POST['h-captcha-response']) ? $_POST['h-captcha-response'] : '';
			$url_path = "https://hcaptcha.com/siteverify";
		} elseif ($captcha_choose == "turnstile") {
			$post_token = isset($_POST['cf-turnstile-response']) ? $_POST['cf-turnstile-response'] : '';
			$url_path = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
		} else {
			// Cap 验证
			$post_token = isset($_POST['cap-token']) ? $_POST['cap-token'] : '';
			if (empty($cap_endpoint)) {
				self::log("Cap API 端点未配置", 'error');
				throw new Exception(_t('验证码配置错误，请联系站长。'));
			}
			$site_key = $filter_set->site_key;
			$url_path = rtrim($cap_endpoint, '/') . '/' . $site_key . '/siteverify';
		}
		
		// 验证token是否存在且非空
		if (!empty($post_token)) {
			$postdata = array('secret' => $secret_key, 'response' => $post_token);
			
			// 为 Cap 验证设置正确的 Content-Type
			$content_type = ($captcha_choose == "cap") ? 
				'Content-Type: application/json' : 
				'Content-Type: application/x-www-form-urlencoded';
			
			$content = ($captcha_choose == "cap") ? 
				json_encode($postdata) : 
				http_build_query($postdata);
				
			$options = array(
				'http' => array(
					'method' => 'POST',
					'header' => $content_type,
					'content' => $content,
					'timeout' => 10
				)
			);
			
			$context = stream_context_create($options);
			
			// 错误处理
			$response = @file_get_contents($url_path, false, $context);
			if ($response === false) {
			    self::log("验证服务连接失败: {$url_path}", 'error');
				throw new Exception(_t('无法连接验证服务，请稍后再试。'));
			}
			
			$response_data = @json_decode($response);
			if (!is_object($response_data)) {
			    self::log("验证响应解析失败: {$response}", 'error');
				throw new Exception(_t('验证响应无效，请刷新页面重试。'));
			}
			
			if ($response_data->success == true) {
				$opt = "none";
				$error = "";
				// 俄文评论处理
				if ($opt == "none" && $filter_set->opt_noru != "none") {
					if (preg_match("/([\x{0400}-\x{04FF}]|[\x{0500}-\x{052F}]|[\x{2DE0}-\x{2DFF}]|[\x{A640}-\x{A69F}]|[\x{1C80}-\x{1C8F}])/u", $comment['text']) > 0) {
						$error = "Error.";
						$opt = $filter_set->opt_noru;
						self::log("评论包含俄文: " . mb_substr($comment['text'], 0, 50, 'UTF-8') . "...", 'filter');
					}
				}
				// 非中文评论处理
				if ($opt == "none" && $filter_set->opt_nocn != "none") {
					if (preg_match("/[\x{4e00}-\x{9fa5}]/u", $comment['text']) == 0) {
						$error = "At least one Chinese character is required.";
						$opt = $filter_set->opt_nocn;
						self::log("评论不含中文: " . mb_substr($comment['text'], 0, 50, 'UTF-8') . "...", 'filter');
					}
				}
				// 禁止词汇处理
				if ($opt == "none" && $filter_set->opt_ban != "none") {
					if (CaptchaPlus_Plugin::check_in($filter_set->words_ban, $comment['text'])) {
						$error = "More friendly, plz :)";
						$opt = $filter_set->opt_ban;
						self::log("评论包含禁止词汇", 'filter');
					}
				}
				// 敏感词汇处理
				if ($opt == "none" && $filter_set->opt_chk != "none") {
					if (CaptchaPlus_Plugin::check_in($filter_set->words_chk, $comment['text'])) {
						$error = "Error.";
						$opt = $filter_set->opt_chk;
						self::log("评论包含敏感词汇", 'filter');
					}
				}
				// 执行操作
				if ($opt == "abandon") {
					Cookie::set('__typecho_remember_text', $comment['text']);
					throw new Exception($error);
				} elseif ($opt == "spam") {
					$comment['status'] = 'spam';
				} elseif ($opt == "waiting") {
					$comment['status'] = 'waiting';
				}
				Cookie::delete('__typecho_remember_text');
				return $comment;
			} else {
			    $error_codes = isset($response_data->{'error-codes'}) ? json_encode($response_data->{'error-codes'}) : '';
			    self::log("验证失败: {$error_codes}", 'verify');
				throw new Exception(_t('验证码验证失败，请刷新页面重试。'));
			}
		} else {
		    self::log("验证令牌为空", 'verify');
			throw new Exception(_t('请完成验证码验证后再提交评论。'));
		}
	}

	/**
	 * 检查 $str 中是否含有 $words_str 中的词汇
	 * 
	 */
	private static function check_in($words_str, $str)
	{
		$words = explode("\n", $words_str);
		if (empty($words)) {
			return false;
		}
		foreach ($words as $word) {
		    $word = trim($word);
		    if (empty($word)) {
		        continue;
		    }
			if (false !== strpos($str, $word)) {
				return true;
			}
		}
		return false;
	}
}