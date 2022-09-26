<?php
define("MACRO_ERR_SUCCESS", 0);
define("MACRO_ERR_NOOPS", 0xFFFFFFFF);

define("MACRO_ERR_INVALID_PARA", 40001);
define("MACRO_ERR_INVALID_HOST", 40002);
define("MACRO_ERR_INVALID_UID", 40003);
define("MACRO_ERR_INVALID_EID", 40004);
define("MACRO_ERR_INVALID_CID", 40005);
define("MACRO_ERR_INVALID_DATA", 40006);//参数无效

define("MACRO_ERR_CHECK_AUTH", 50001);
define("MACRO_ERR_CHECK_ACCESS", 50002);
define("MACRO_ERR_CHECK_EMPTY", 50003); //空
define("MACRO_ERR_CHECK_DUP", 50004);
define("MACRO_ERR_CHECK_FMT", 50005);
define("MACRO_ERR_CHECK_MAX", 50006);
define("MACRO_ERR_CHECK_BLACK", 50007);//账号有误
define("MACRO_ERR_CHECK_WARN", 50008);//登录页面提示登录（付费或登录到期）
define("MACRO_ERR_CHECK_SQL", 50009);//mysql错误
define("MACRO_ERR_BLACK_USER", 50010);//黑名单用户（禁止登录）

define("MACRO_ERR_NEED_USER", 60001);
define("MACRO_ERR_INVALID_USER", 60002);//用户无效
class Base
{
    public $_pass_fun_token = array(
        '_sms',
        '_login',
        '_wxlogin',
        '_wxregister',
        '_location',
        '_lst_kindergarten',
        '_pcregister',
        '_get_activity_detail',
//        '_get_teach_plan',
        '_web_ku_login',
        '_getSessionId',
        '_checkLogin',
        '_getwxCode',
        '_rigetCodeWx'
    );//允许固定的接口携带固定的token访问
    public $_pass_fun_no_token = array('_getSessionId', '_checkLogin', '_getwxCode', '_rigetCodeWx');//允许固定的接口不携带token访问
    private $_key = 'zhengjiniu';//key
    private $_public_token = 'MTIsemhlbmdqaW5pdSwxNTU4Njk4MDQ';//允许用户端固定token访问
    private $_type_zino = array(1, 2, 3, 4, 5); //用于区分pc和小程序来源--type 1web 2手机 3yy 4官网 5客户端

    //平台接口token验证
    public function verify_token($send_token = '', $my_token = '', $type = 1)
    {
        $send_array = $this->decode_token($send_token);
        $my_array = $this->decode_token($my_token);
        //判断uid
        if ($send_array[0] != $my_array[0]) {
            return false;
        }
        //判断type 1web 2手机 3yy 4官网 5客户端uid相同，手机,官网和pc不能互踢
        if ((($type != $my_array[2] && ($type == 2 || $my_array[2] == 2)) || $type == 4) && in_array($type,
                array(1, 2, 4, 5))) {
            $before_time = intval($send_array[4]) - 60 * 60 * 24 * 7;
            if ($my_array[4] > $before_time) {
                return $send_array[4] + 2;
            }
            return false;
        }
        //判断key
        if ($send_array[3] != $my_array[3]) {
            return false;
        }
        //判断时间
        /*		$my_array[4] = '1558926736';
                $send_array[4] = '1558926736';*/
        $before_time = intval($send_array[4]) - 60;
        $later_time = intval($send_array[4]) + 60;
        //允许2秒误差的请求
        if ($send_array[4] == $my_array[4]) {
            return $my_array[4] + 2;
        }
        if ($my_array[4] < $later_time && $my_array[4] > $before_time) {
            return $send_array[4] + 2;
        }
        return false;
    }

//产生令牌
    public function encode_token($uid = '', $type = 1, $first = 0, $token_time = '')
    {
        if ($first == 1) {
            $time = time();
        } else {
            $time = $token_time + 2;
        }
        $token = base64_encode($uid . ',' . random_int(10000, 9999999) . ',' . $type . ',' . $this->_key . ',' . $time);
        return $token;
    }

//令牌解密
    public function decode_token($token = '')
    {
        $token = base64_decode($token);
        $array = explode(',', $token);
        return $array;
    }

    public function _parse($func, $method, $get_paras, $post_paras, $option_paras)
    {

        $input = array();
        // 提取GET参数
        if (!empty($get_paras)) {
            foreach ($get_paras as $v) {
                if (!isset($_GET["$v"])) {
                    $input['errcode'] = MACRO_ERR_INVALID_PARA;
                } else {
                    $input["$v"] = $_GET["$v"];
                }
            }
        }
        if (!empty($option_paras)) {
            foreach ($option_paras as $v) {
                if (isset($_GET["$v"])) {
                    $input["$v"] = $_GET["$v"];
                }
            }
        }

        // 提取POST参数
        if ($method == 'post') {
            if (!empty($post_paras)) {
                $raw = json_decode(file_get_contents("php://input"), true);
                foreach ($post_paras as $v) {
                    if (!isset($raw["$v"])) {
                        $input['errcode'] = MACRO_ERR_INVALID_PARA;
                    } else {
                        $input["$v"] = $raw["$v"];
                    }
                }
                if (!empty($option_paras)) {
                    foreach ($option_paras as $v) {
                        if (isset($raw["$v"])) {
                            $input["$v"] = $raw["$v"];
                        }
                    }
                }
            } else {
                $input['raw'] = file_get_contents("php://input");
            }
        }
        if ($method == 'put') {
            $input['raw'] = file_get_contents("php://input");
        }

        $user = array('token' => '');
        if (!empty($this->getHeader()) && !empty($this->getHeader()['TOKEN']) && !empty($this->getHeader()['TYPE'])) {
            //用于区分pc和小程序来源--type 1web 2手机 3yy 4官网 5客户端 uid相同，手机,官网和pc不能互踢,
            $header_token = $this->getHeader()['TOKEN'];
            $header_type = $this->getHeader()['TYPE'];
            $input['source_type'] = $header_type;
            switch ($header_type) {
                case 3:
                    //验证运营token;
                    $is_yy = $this->yy_verify_token($header_token);
                    $is_yy = true;
                    if (!$is_yy) {
                        $input['errcode'] = MACRO_ERR_CHECK_BLACK;
                    }
                    break;
                case 5:
                case 4:
                case 2:
                case 1:
                    //1.当第一次访问没有token时,通过设定方法
                    if (in_array($func, $this->_pass_fun_token)) {
                        if ($header_token != $this->_public_token || !in_array($header_type, $this->_type_zino)) {
                            $input['errcode'] = MACRO_ERR_CHECK_BLACK;
                        }
                        //规则符合的话，需分别在对应方法中加入:产生token->入库->返回token
                    } else {
                        //2.当正常访问有tokens时，验证token
                        //查询uid对应的token
                        if (isset($input['uid'])) {
                            $user = $this->_checkUid($input['uid']);
                        }
                        //判断token是否合法
                        $token_time = $this->verify_token($header_token, $user['token'], $header_type);
                        if ($token_time) {
                            //					dump('通过');
                            //得到新token
                            $now_token = $this->encode_token($input['uid'], $header_type, 0, $token_time);
                            //token入库并返回到前端
                            $add_ok = $this->_add_token($input['uid'], $now_token);
                            if (!$add_ok) {
                                $input['errcode'] = MACRO_ERR_CHECK_BLACK;
                            }
                            $this->_return_header($now_token);
                        } else {
                            //-失败;
                            $input['errcode'] = MACRO_ERR_CHECK_BLACK;
                        }
                    }
                    break;
                default:
                    $input['errcode'] = MACRO_ERR_CHECK_BLACK;

            }
        } else {
            if (!in_array($func, $this->_pass_fun_no_token)) {
                $input['errcode'] = MACRO_ERR_CHECK_BLACK;
            }
        }
        $input['source_type'] = 1;
        return $input;
    }

    //header响应输出token
    public function _return_header($token = '')
    {
        header('return_token:' . $token);
    }

    //运营接口token验证
    public function yy_verify_token($send_token = '')
    {
        $ip = $_SERVER["REMOTE_ADDR"];
        $in = array('60.205.212.177', '172.17.108.61');
        if (!in_array($ip, $in)) {
            return false;
        }
        //算法
//		$token = base64_encode(time().',3,'.$this->_key.','.random_int(10000,9999999));
//		dump($token);
        $send_array = $this->decode_token($send_token);
        //判断type 1pc 2手机,3运营
        if ($send_array[1] != 3) {
            return false;
        }
        //判断key
        if ($send_array[2] != $this->_key) {
            return false;
        }
        //判断时间
        $before_time = time() - 3600;
        $later_time = time() + 3600;
        //允许30秒误差的请求
        if ($send_array[3] < $later_time && $send_array[3] > $before_time) {
            return true;
        }
        return false;
    }

    public function getHeader()
    {
        $headers = array();
        foreach ($_SERVER as $key => $value) {
            if ('HTTP_' == substr($key, 0, 5)) {
                $headers[str_replace('_', '-', substr($key, 5))] = $value;
            }
            if (isset($_SERVER['PHP_AUTH_DIGEST'])) {
                $header['AUTHORIZATION'] = $_SERVER['PHP_AUTH_DIGEST'];
            } elseif (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
                $header['AUTHORIZATION'] = base64_encode($_SERVER['PHP_AUTH_USER'] . ':' . $_SERVER['PHP_AUTH_PW']);
            }
            if (isset($_SERVER['CONTENT_LENGTH'])) {
                $header['CONTENT-LENGTH'] = $_SERVER['CONTENT_LENGTH'];
            }
            if (isset($_SERVER['CONTENT_TYPE'])) {
                $header['CONTENT-TYPE'] = $_SERVER['CONTENT_TYPE'];
            }
        }
        return $headers;
    }
}
