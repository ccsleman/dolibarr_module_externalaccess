<?php // Protection to avoid direct call of template
if (empty($context) || ! is_object($context))
{
    print "Error, template page can't be called as URL";
    exit;
    // Note: use fontawesome v4.7.0 : https://fontawesome.com/v4.7.0/
}

global $langs;
?>

	<section id="services">
      <div class="container">
        <div class="row">
          <div class="col-lg-12 text-center">
            <h2 class="section-heading"><?php print $langs->trans('Error404');  ?></h2>
            <hr class="my-4">
          </div>
        </div>
      </div> 
      <div class="container">
        <p class="text-center" ><?php print $langs->trans('SorryThereIsNothingHere');  ?></p>
      </div>
    </section>