<?php
/* Copyright (C) 2002-2007	Rodolphe Quiedeville	<rodolphe@quiedeville.org>
 * Copyright (C) 2003		Xavier Dutoit			<doli@sydesy.com>
 * Copyright (C) 2004-2012	Laurent Destailleur		<eldy@users.sourceforge.net>
 * Copyright (C) 2004		Sebastien Di Cintio		<sdicintio@ressource-toi.org>
 * Copyright (C) 2004		Benoit Mortier			<benoit.mortier@opensides.be>
 * Copyright (C) 2005-2017	Regis Houssin			<regis.houssin@inodbox.com>
 * Copyright (C) 2005		Simon Tosser			<simon@kornog-computing.com>
 * Copyright (C) 2006		Andre Cianfarani		<andre.cianfarani@acdeveloppement.net>
 * Copyright (C) 2010		Juanjo Menent			<jmenent@2byte.es>
 * Copyright (C) 2011		Philippe Grand			<philippe.grand@atoo-net.com>
 * Copyright (C) 2014		Teddy Andreotti			<125155@supinfo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 *	\file       htdocs/master.inc.php
 * 	\ingroup	core
 *  \brief      File that defines environment for all Dolibarr process (pages or scripts)
 * 				This script reads the conf file, init $lang, $db and and empty $user
 */

// Include the conf.php and functions.lib.php and security.lib.php. This defined the constants like DOL_DOCUMENT_ROOT, DOL_DATA_ROOT, DOL_URL_ROOT...
// This file may have been already required by main.inc.php. But may not by scripts. So, here the require_once must be kept.
require_once $dir.'filefunc.inc.php';


if (!function_exists('is_countable')) {
	/**
	 * function is_countable (to remove when php version supported will be >= 7.3)
	 * @param mixed $c data to check if countable
	 * @return bool
	 */
	function is_countable($c)
	{
		return is_array($c) || $c instanceof Countable;
	}
}

/*
 * Create $conf object
 */

require_once DOL_DOCUMENT_ROOT.'/core/class/conf.class.php';

$conf = new Conf();

// Set properties specific to database
$conf->db->host = empty($dolibarr_main_db_host) ? '' : $dolibarr_main_db_host;
$conf->db->port = empty($dolibarr_main_db_port) ? null : $dolibarr_main_db_port;
$conf->db->name = empty($dolibarr_main_db_name) ? '' : $dolibarr_main_db_name;
$conf->db->user = empty($dolibarr_main_db_user) ? '' : $dolibarr_main_db_user;
$conf->db->pass = empty($dolibarr_main_db_pass) ? '' : $dolibarr_main_db_pass;
$conf->db->type = $dolibarr_main_db_type;
$conf->db->prefix = $dolibarr_main_db_prefix;
$conf->db->character_set = $dolibarr_main_db_character_set;
$conf->db->dolibarr_main_db_collation = $dolibarr_main_db_collation;
$conf->db->dolibarr_main_db_encryption = $dolibarr_main_db_encryption;
$conf->db->dolibarr_main_db_cryptkey = $dolibarr_main_db_cryptkey;
if (defined('TEST_DB_FORCE_TYPE')) {
	$conf->db->type = constant('TEST_DB_FORCE_TYPE'); // Force db type (for test purpose, by PHP unit for example)
}

// Set properties specific to conf file
$conf->file->main_limit_users = $dolibarr_main_limit_users;
$conf->file->mailing_limit_sendbyweb = empty($dolibarr_mailing_limit_sendbyweb) ? 0 : $dolibarr_mailing_limit_sendbyweb;
$conf->file->mailing_limit_sendbycli = empty($dolibarr_mailing_limit_sendbycli) ? 0 : $dolibarr_mailing_limit_sendbycli;
$conf->file->mailing_limit_sendbyday = empty($dolibarr_mailing_limit_sendbyday) ? 0 : $dolibarr_mailing_limit_sendbyday;
$conf->file->main_authentication = empty($dolibarr_main_authentication) ? 'dolibarr' : $dolibarr_main_authentication; // Identification mode
$conf->file->main_force_https = empty($dolibarr_main_force_https) ? '' : $dolibarr_main_force_https; // Force https
$conf->file->strict_mode = empty($dolibarr_strict_mode) ? '' : $dolibarr_strict_mode; // Force php strict mode (for debug)
$conf->file->instance_unique_id = empty($dolibarr_main_instance_unique_id) ? (empty($dolibarr_main_cookie_cryptkey) ? '' : $dolibarr_main_cookie_cryptkey) : $dolibarr_main_instance_unique_id; // Unique id of instance
$conf->file->dol_document_root = array('main' => (string) DOL_DOCUMENT_ROOT); // Define array of document root directories ('/home/htdocs')
$conf->file->dol_url_root = array('main' => (string) DOL_URL_ROOT); // Define array of url root path ('' or '/dolibarr')
if (!empty($dolibarr_main_document_root_alt)) {
	// dolibarr_main_document_root_alt can contains several directories
	$values = preg_split('/[;,]/', $dolibarr_main_document_root_alt);
	$i = 0;
	foreach ($values as $value) {
		$conf->file->dol_document_root['alt'.($i++)] = (string) $value;
	}
	$values = preg_split('/[;,]/', $dolibarr_main_url_root_alt);
	$i = 0;
	foreach ($values as $value) {
		if (preg_match('/^http(s)?:/', $value)) {
			// Show error message
			$correct_value = str_replace($dolibarr_main_url_root, '', $value);
			print '<b>Error:</b><br>'."\n";
			print 'Wrong <b>$dolibarr_main_url_root_alt</b> value in <b>conf.php</b> file.<br>'."\n";
			print 'We now use a relative path to $dolibarr_main_url_root to build alternate URLs.<br>'."\n";
			print 'Value found: '.$value.'<br>'."\n";
			print 'Should be replaced by: '.$correct_value.'<br>'."\n";
			print "Or something like following examples:<br>\n";
			print "\"/extensions\"<br>\n";
			print "\"/extensions1,/extensions2,...\"<br>\n";
			print "\"/../extensions\"<br>\n";
			print "\"/custom\"<br>\n";
			exit;
		}
		$conf->file->dol_url_root['alt'.($i++)] = (string) $value;
	}
}

// Chargement des includes principaux de librairies communes
if (!defined('NOREQUIREUSER')) {
	require_once DOL_DOCUMENT_ROOT.'/user/class/user.class.php'; // Need 500ko memory
}
if (!defined('NOREQUIRETRAN')) {
	require_once DOL_DOCUMENT_ROOT.'/core/class/translate.class.php';
}
if (!defined('NOREQUIRESOC')) {
	require_once DOL_DOCUMENT_ROOT.'/societe/class/societe.class.php';
}


/*
 * Creation objet $langs (must be before all other code)
 */
if (!defined('NOREQUIRETRAN')) {
	$langs = new Translate('', $conf); // Must be after reading conf
}

/*
 * Object $db
 */
$db = null;
if (!defined('NOREQUIREDB')) {
	$db = getDoliDBInstance($conf->db->type, $conf->db->host, $conf->db->user, $conf->db->pass, $conf->db->name, $conf->db->port);

	if ($db->error) {
		// If we were into a website context
		if (!defined('USEDOLIBARREDITOR') && !defined('USEDOLIBARRSERVER') && !empty($_SERVER['SCRIPT_FILENAME']) && (strpos($_SERVER['SCRIPT_FILENAME'], DOL_DATA_ROOT.'/website') === 0)) {
			$sapi_type = php_sapi_name();
			if (substr($sapi_type, 0, 3) != 'cgi') {
				http_response_code(503); // To tel search engine this is a temporary error
			}
			print '<div class="center" style="text-align: center; margin: 100px;">';
			if (is_object($langs)) {
				$langs->setDefaultLang('auto');
				$langs->load("website");
				print $langs->trans("SorryWebsiteIsCurrentlyOffLine");
			} else {
				print "SorryWebsiteIsCurrentlyOffLine";
			}
			print '</div>';
			exit;
		}
		dol_print_error($db, "host=".$conf->db->host.", port=".$conf->db->port.", user=".$conf->db->user.", databasename=".$conf->db->name.", ".$db->error);
		exit;
	}
}

// Now database connexion is known, so we can forget password
//unset($dolibarr_main_db_pass); 	// We comment this because this constant is used in some other pages
unset($conf->db->pass); // This is to avoid password to be shown in memory/swap dump


/*
 * Object $user
 */
if (!defined('NOREQUIREUSER')) {
	$user = new User($db);
}


/*
 * Load object $conf
 */
$entitytotest = false;
if (!defined('NOREQUIREDB')) {
	require_once __DIR__.'/class/context.class.php';
	$entitytotest = Context::getEntityMappingForCurrentDomain();
	if($entitytotest){
		$conf->entity = $entitytotest;
	}
}

if(empty($entitytotest)){
	// By default conf->entity is 1, but we change this if we ask another value.
	if (session_id() && !empty($_SESSION["dol_entity"])) {
		// Entity inside an opened session
		$conf->entity = $_SESSION["dol_entity"];
	} elseif (!empty($_ENV["dol_entity"])) {
		// Entity inside a CLI script
		$conf->entity = $_ENV["dol_entity"];
	} elseif (GETPOSTISSET("loginfunction") && GETPOST("entity", 'int')) {
		// Just after a login page
		$conf->entity = GETPOST("entity", 'int');
	} elseif (defined('DOLENTITY') && is_numeric(constant('DOLENTITY'))) {
		// For public page with MultiCompany module
		$conf->entity = constant('DOLENTITY');
	}
}

// Sanitize entity
if (!is_numeric($conf->entity)) {
	$conf->entity = 1;
}
// Here we read database (llx_const table) and define $conf->global->XXX var.
//print "We work with data into entity instance number '".$conf->entity."'";
$conf->setValues($db);

// Create object $mysoc (A thirdparty object that contains properties of companies managed by Dolibarr.
if (!defined('NOREQUIREDB') && !defined('NOREQUIRESOC')) {
	require_once DOL_DOCUMENT_ROOT.'/societe/class/societe.class.php';

	$mysoc = new Societe($db);
	$mysoc->setMysoc($conf);

	// We set some specific default values according to country

	if ($mysoc->country_code == 'DE' && !isset($conf->global->MAIN_INVERT_SENDER_RECIPIENT)) {
		// For DE, we need to invert our address with customer address
		$conf->global->MAIN_INVERT_SENDER_RECIPIENT = 1;

	}
	if ($mysoc->country_code == 'FR' && !isset($conf->global->MAIN_PROFID1_IN_ADDRESS)) {
		// For FR, default value of option to show profid SIRET is on by default
		$conf->global->MAIN_PROFID1_IN_ADDRESS = 1;
	}

	if (($mysoc->localtax1_assuj || $mysoc->localtax2_assuj) && !isset($conf->global->MAIN_NO_INPUT_PRICE_WITH_TAX)) {
		// For countries using the 2nd or 3rd tax, we disable input/edit of lines using the price including tax (because 2nb and 3rd tax not yet taken into account).
		// Work In Progress to support all taxes into unit price entry when MAIN_UNIT_PRICE_WITH_TAX_IS_FOR_ALL_TAXES is set.
		$conf->global->MAIN_NO_INPUT_PRICE_WITH_TAX = 1;
	}
}


// Set default language (must be after the setValues setting global getDolGlobalString('MAIN_LANG_DEFAULT'). Page main.inc.php will overwrite langs->defaultlang with user value later)
if (!defined('NOREQUIRETRAN')) {
	$langcode = (GETPOST('lang', 'aZ09') ? GETPOST('lang', 'aZ09', 1) : (getDolGlobalString('MAIN_LANG_DEFAULT','auto' )));
	if (defined('MAIN_LANG_DEFAULT')) {	// So a page can force the language whatever is setup and parameters in URL
		$langcode = constant('MAIN_LANG_DEFAULT');
	}
	$langs->setDefaultLang($langcode);
}


// Create the global $hookmanager object
include_once DOL_DOCUMENT_ROOT.'/core/class/hookmanager.class.php';
$hookmanager = new HookManager($db);


if (!defined('MAIN_LABEL_MENTION_NPR')) {
	define('MAIN_LABEL_MENTION_NPR', 'NPR');
}
//if (! defined('PCLZIP_TEMPORARY_DIR')) define('PCLZIP_TEMPORARY_DIR', $conf->user->dir_temp);
