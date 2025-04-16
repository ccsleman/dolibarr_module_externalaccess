<?php

require_once __DIR__ . '/../class/user_external_access.class.php';

class NewuserController extends Controller
{
	/**
	 * Store var for template
	 * @var stdClass
	 */
	public $tpl;

	public function __construct() {
		$this->accessNeedLoggedUser = false;
		$this->tpl = new stdClass();
	}

	/**
	 * check current access to controller
	 *
	 * @param void
	 * @return  bool
	 */
	public function checkAccess() {
		global $conf;
		$this->accessNeedLoggedUser = false;
		$this->accessRight =  true; // personal information always available
		return parent::checkAccess();
	}

	/**
	 * action method is called before html output
	 * can be used to manage security and change context
	 *
	 * @param void
	 * @return void
	 */
	public function action(){
		global $langs, $conf,$dolibarr_main_authentication, $db, $user;
		$context = Context::getInstance();

		$context->doNotDisplayHeaderBar = 1;
		$context->doNotDisplayMenu = 0;


		// Load translation files required by page
		$langs->loadLangs(array('errors', 'users', 'companies', 'ldap', 'other'));


		$this->username = GETPOST('username', 'alphanohtml');
		$this->passwordhash = GETPOST('passwordhash', 'alpha');

		//$parameters = array('username' => $this->username);

		//$hookRes = $this->hookDoAction($parameters);
		$hookRes = 0;


		// init tpl vars;
		$this->tpl->message = '';

		$this->tpl->mode = $dolibarr_main_authentication;
		if (!$this->tpl->mode) $this->tpl->mode = 'http';

		// Security graphical code
		$this->tpl->captcha = 0;
		if (function_exists("imagecreatefrompng")){
			$this->tpl->captcha = 1;
		}


		if(empty($hookRes)){
			$context->title = $langs->trans('Welcome');
			$context->desc = $langs->trans('WelcomeDesc');

			/*  */


			// Validate new password
			if ($context->action == 'validatenewpassword' && $this->username && $this->passwordhash)
			{
				$edituser = new UserExternalAccess($db);
				$result = $edituser->fetch('', $_GET["username"]);

				if ($result < 0)
				{
					$this->tpl->message.= '<div class="text-danger">'.dol_escape_htmltag($langs->trans("ErrorLoginDoesNotExists", $this->username)).'</div>';
				} else {
					if (dol_verifyHash($edituser->pass_temp, $this->passwordhash))
					{
						// Clear session
						unset($_SESSION['dol_login']);
						$_SESSION['dol_loginmesg'] = $langs->trans('NewPasswordValidated'); // Save message for the session page

						$newpassword = $edituser->setPassword($user, $edituser->pass_temp, 0);
						dol_syslog("passwordforgotten.php new password for user->id=".$edituser->id." validated in database");
						header("Location: ".$context->getControllerUrl());
						exit;
					} else {
						$langs->load("errors");
						$this->tpl->message.= '<div class="text-danger">'.$langs->trans("ErrorFailedToValidatePasswordReset").'</div>';
					}
				}
			}
			// Action envoyer le code de validation
			if ($context->action == 'sendemail' && $this->username)
			{
				$error = 0;
				$errmsg = '';
				$sessionkey = 'dolexternal_antispam_value';
				$ok = (array_key_exists($sessionkey, $_SESSION) === true && (strtolower($_SESSION[$sessionkey]) == strtolower($_POST['code'])));

				// Verify code
				if (!$ok)
				{
					$this->tpl->message.= '<div class="text-danger">'.$langs->trans("ErrorBadValueForCode").'</div>';
				}
				
				if (!GETPOST("lastname")) {
					$error++;
					$errmsg .= $langs->trans("ErrorFieldRequired", $langs->transnoentitiesnoconv("Nom"))."<br>\n";
				}
				if (!GETPOST("firstname")) {
					$error++;
					$errmsg .= $langs->trans("ErrorFieldRequired", $langs->transnoentitiesnoconv("Prénom"))."<br>\n";
				}
				if (!GETPOST("password")) {
					$error++;
					$errmsg .= $langs->trans("ErrorFieldRequired", $langs->transnoentitiesnoconv("Password"))."<br>\n";
				}
				if (!GETPOST("password2")) {
					$error++;
					$errmsg .= $langs->trans("ErrorFieldRequired", $langs->transnoentitiesnoconv("Password"))."<br>\n";
				}
				if (GETPOST("username") && !isValidEmail(GETPOST("username"))) {
					$error++;
					$langs->load("errors");
					$errmsg .= $langs->trans("ErrorBadEMail", GETPOST("username"))."<br>\n";
				}
				if (GETPOST("password2") != GETPOST("password")) {
					$error++;
					$langs->load("errors");
					$errmsg .= "Les mots de passe ne sont pas identiques"."<br>\n";
				}

				if (!$error) {
					$db->begin();
					// Check if email already exists
					$user = new User($db);
					$filter = array('email'=>$this->username, 'login'=>GETPOST("username"));
			
					// Check if there is already an attendee into table eventorganization_conferenceorboothattendee for same event (or conference/booth)
					$resultFetchUser = $user->fetchAll('', '', 0, 0, $filter,"OR");
			
					if (is_array($resultFetchUser) && count($resultFetchUser) > 0) {
						// Found login
						$knownuser = 1;
					} else {
						// Need to create a user
						require_once DOL_DOCUMENT_ROOT.'/core/lib/security2.lib.php';
						$knownuser = 0;
						$user->datec = dol_now();
						$user->login = GETPOST("username");
						$user->email = GETPOST("username");
						$user->api_key = getRandomPassword();
						$user->admin = 0;
						$user->employee = 0;
						$user->status = 0;
						//$user->setPassword($user, $password = '', $changelater = 0, $notrigger = 0, $nosyncmember = 0, $passwordalreadycrypted = 0)
						// Crypt password
						$password_crypted = dol_hash(GETPOST("password"));
						$user->pass_indatabase_crypted = $password_crypted;
						//$user->pass_crypted = $password_crypted;
						$readyuser = $user->create($user);
					}
					if ($readyuser < 0) {
						$error++;
						$errmsg .= $user->error;
						//$errors = array_merge($errors, $user->errors);
					}
				}
				if (!$error) {
					$db->commit();
			
					// Sending mail
					require_once DOL_DOCUMENT_ROOT.'/core/class/CMailFile.class.php';
					include_once DOL_DOCUMENT_ROOT.'/core/class/html.formmail.class.php';
					$formmail = new FormMail($db);
					// Set output language
					$outputlangs = new Translate('', $conf);
					$outputlangs->setDefaultLang($mysoc->default_lang);
					// Load traductions files required by page
					$outputlangs->loadLangs(array("main", "members"));
					// Get email content from template
					$arraydefaultmessage = null;
			
					$labeltouse = '{EnvoiValidationUser}';
					if (!empty($labeltouse)) {
						$arraydefaultmessage = $formmail->getEMailTemplate($db, 'user', $user, $outputlangs, $labeltouse, 1, '');
					}
			
					if (!empty($labeltouse) && is_object($arraydefaultmessage) && $arraydefaultmessage->id > 0) {
						$subject = $arraydefaultmessage->topic;
						$msg     = $arraydefaultmessage->content;
					}
			
					$substitutionarray = getCommonSubstitutionArray($outputlangs, 0, null, $user);
					complete_substitutions_array($substitutionarray, $outputlangs, $object);
			
					$subjecttosend = make_substitutions($subject, $substitutionarray, $outputlangs);
					$redirection = $dolibarr_main_url_root.'/public/eventorganization/subscriptionok.php?id='.((int) $id).'&securekey='.urlencode($securekeyurl);
					$texttosend = make_substitutions($msg, $substitutionarray, $outputlangs);
					$texttosend = $texttosend."<p>Code de validation: ".$user->api_key."</p>";
					$texttosend = $texttosend.'<p><a href="'.$dolibarr_main_url_root.'/externalaccess/www/subscriptionok.php?id='.$user->api_key.'">Valider en cliquant ici</a></p>';
			
					$sendto = $user->email;
					$from = $conf->global->MAILING_EMAIL_FROM;
					$urlback = $_SERVER["REQUEST_URI"];
			
					$ishtml = dol_textishtml($texttosend); // May contain urls
			
					$mailfile = new CMailFile($subjecttosend, $sendto, $from, $texttosend, array(), array(), array(), '', '', 0, $ishtml);
			
					$result = $mailfile->sendfile();
					if ($result) {
						dol_syslog("EMail sent to ".$sendto, LOG_DEBUG, 0);
					} else {
						dol_syslog("Failed to send EMail to ".$sendto, LOG_ERR, 0);
					}
			
					//$redirection = $dolibarr_main_url_root.'/externalaccess/www/subscriptionok.php';
			
					//Header("Location: ".$redirection);
					//exit;
				} else {
					$db->rollback();
					//$paramsurl=array();
					//if (GETPOST('textbrowser','int')) $paramsurl[]='textbrowser='.GETPOST('textbrowser','int');
					//if (GETPOST('nojs','int'))        $paramsurl[]='nojs='.GETPOST('nojs','int');
					//if (GETPOST('lang','aZ09'))       $paramsurl[]='lang='.GETPOST('lang','aZ09');
					//header('Location: '.$_SERVER['PHP_SELF'].(count($paramsurl)?'?'.implode('&',$paramsurl):''));
					//exit;
				}

				if ($error) {
					$this->tpl->message.= '<div class="text-danger">'.$errmsg.'</div>';
				}
				
			}
		}
	}


	/**
	 *
	 * @param void
	 * @return void
	 */
	public function display(){
		global $conf, $langs;

		$this->loadTemplate('header');

		$hookRes = $this->hookPrintPageView();

		if(empty($hookRes)){

			?>
			<header class="masthead text-center  d-flex">
				<div class="container my-auto">
					<?php
					$this->loadTemplate('form.newuser');
					?>
				</div>
			</header>
			<?php

		}

		$this->loadTemplate('footer');
	}
}
