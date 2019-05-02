<?php
/**
 * Plugin Name:      RW Matrix Synapse REST Auth
 * Plugin URI:       https://github.com/rpi-virtuell/rw-matrix-synapse-rest-auth
 * Description:	     REST Endpoint for https://github.com/kamax-matrix/matrix-synapse-rest-auth to login with WordPress User into a Matrix Homeserver
 * Author:           Frank Neumann-Staude
 * Version:          1.0.0
 * Licence:          GPLv3
 * Author URI:       http://staude.net
 * GitHub Plugin URI: https://github.com/rpi-virtuell/rw-matrix-synapse-rest-auth
 * GitHub Branch:     master
 */

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
			$password= $requestObj->user->password;

			$LoginUser = wp_authenticate( $user, $password );
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
}