<?php
/**
 * Plugin Name:      RW Matrix Synapse REST Auth
 * Plugin URI:       https://github.com/rpi-virtuell/rw-matrix-synapse-rest-auth
 * Description:	     REST Endpoint for https://github.com/kamax-matrix/matrix-synapse-rest-auth to login with WordPress User into a Matrix Homeserver
 * Author:           Frank Neumann-Staude
 * Version:          1.2.0
 * Licence:          GPLv3
 * Author URI:       http://staude.net
 * GitHub Plugin URI: https://github.com/rpi-virtuell/rw-matrix-synapse-rest-auth
 * GitHub Branch:     master
 */

if(!defined('MATRIX_HOMESERVER_URL')){
	define('MATRIX_HOMESERVER_URL', 'https://matrix.rpi-virtuell.de');
}
if(!defined('MATRIX_DOMAIN')){
	define('MATRIX_DOMAIN', 'rpi-virtuell.de');
}

class MatrixSynapseRESTAuth {

	static public $api_endpoint = '_matrix-internal/identity/v1';

	static private $instance = NULL;

	/**
	 * Plugin constructor.
	 *
	 * @since   0.1
	 * @access  public
	 * @uses    plugin_basename
	 * @action  rw_remote_auth_server_init
	 */
	public function __construct() {
		add_action( 'rest_api_init', 'register_matrixsynapse_rest_routes' );
		add_action( 'init', array( 'MatrixSynapseRESTAuth', 'add_endpoint' ), 0 );
		add_action( 'init', array( $this, 'on_action_do_matrix_login' ));
		add_action( 'init', array( $this, 'on_action_mgetuser' ));
	}


	/**
	 * Creates an Instance of this Class
	 *
	 * @since   0.1
	 * @access  public
	 * @return  RW_Remote_Auth_Server
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self;
		}

		return self::$instance;
	}

	/**
	 * Add API Endpoint
	 *
	 * @since   0.1
	 * @access  public
	 * @static
	 * @return void
	 */
	static public function add_endpoint() {
		add_rewrite_rule( '^' . MatrixSynapseRESTAuth::$api_endpoint . '/([^/]*)/?', 'wp-json/matrix-synapse/v1/$1', 'top' );
		flush_rewrite_rules();
	}

	/**
     * redirects to Matrix login server id url param action=mlogin
     *
     * @since 1.2.0
     * @action init
	 */
	public function on_action_do_matrix_login(){
		if(is_user_logged_in() && isset($_GET['action'])&&'mlogin' === $_GET['action']){
			$me = wp_get_current_user();
            $hash = base64_encode(wp_generate_password(24));
			update_user_meta($me->ID,'matrix_login_hash', $hash);
            wp_redirect(MATRIX_HOMESERVER_URL.'/?token='.$hash);
			die();
		}elseif( isset($_GET['action'])&&'mlogin' === $_GET['action']){
			wp_redirect(MATRIX_HOMESERVER_URL);
            die();
        }
	}

    public function on_action_mgetuser(){
		if(is_user_logged_in() && isset($_POST['action'])&&'mgetuser' === $_POST['action'] && isset($_POST['token'])){

			$return = ['success'=>false];

			$token = $_POST['token'];
			if(strlen($token)>1){
				$users = get_users( array(
					'meta_query' => array(
						array(
							'key'     => 'matrix_login_hash',
							'value'   => $token,
							'compare' => '=',
						)
					),
				) );

				if($users){
					$user = $users[0];
					$return=[
						'success'=>true,
						'mxid'=>$user->user_login,
						'password'=> $token
					];
				}
			}
			switch ($_SERVER['HTTP_ORIGIN']) {
				case 'http://matrix.rpi-virtuell.de':

					header('Access-Control-Allow-Origin: '.$_SERVER['HTTP_ORIGIN']);
					header('Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS');
					header('Access-Control-Max-Age: 1000');
					header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

				break;
			}
			header('Content-Type: application/json; charset=utf-8');
			echo json_encode($return);
			die();

        }
	}



}

if ( class_exists( 'MatrixSynapseRESTAuth' ) ) {
	add_action( 'plugins_loaded', array( 'MatrixSynapseRESTAuth', 'get_instance' ) );
}

function register_matrixsynapse_rest_routes (){
	$controller = new MatrixSynapseRESTAuthAPI();
	$controller->register_routes();
}

class MatrixSynapseRESTAuthAPI extends   WP_REST_Controller {
	/**
	 * Register the routes for the objects of the controller.
	 */
	public function register_routes() {
		$version = '1';
		$namespace = 'matrix-synapse/v' . $version;
		$base = 'check_credentials';
		register_rest_route( $namespace, '/' . $base, array(
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'check_credentials' ),
				'args'                => array(
					'page' => array (
						'required' => false
					),
					'per_page' => array (
						'required' => false
					),
				),
			),
		) );
	}

	public function check_credentials( WP_REST_Request $request ) {
		$request = $request->get_body() ;
		$requestObj = json_decode( $request );
		if ( null === $requestObj ) {
			$data = array( 'auth' => array( "success" => false ) );
		} else {
			$user = $requestObj->user->id;
			$mxid = $user;
            $user = substr( $user, 1, strpos( $user, ':' ) -1);
            $password= addslashes($requestObj->user->password);

			$MatrixUser = $this->get_user_by_matrix_hash($user, $password);
			if($MatrixUser){
				$LoginUser =  $MatrixUser;
				$mxid = '@'.$LoginUser->user_login.':'.MATRIX_DOMAIN;
            }else{
				$LoginUser = wp_authenticate( $user, $password );
            }
			if ( !is_wp_error( $LoginUser ) ) {
				$data  = array( 'auth' => array(
					"success" => true,
					"mxid" =>  $mxid,
					"profile" => array(
						"display_name" => $LoginUser->display_name,
					),
				));
			} else {
				$data = array( 'auth' => array( "success" => false ) );
			}

		}

		$response = new WP_REST_Response( $data );

		$response->set_status( 201 );
		return $response;
	}

	private function get_user_by_matrix_hash($user,$password){


			$users =  get_users(array(
				'meta_key' => 'matrix_login_hash',
				'meta_value' => $password,
				'compare' => '=',
			));
			if(count($users)>0){
				$user = $users[0];
				delete_user_meta($user->ID,'matrix_login_hash');
				return $user;
			}


		return false;
	}
}
