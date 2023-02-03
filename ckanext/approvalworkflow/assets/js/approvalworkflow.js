$("#field-approval-workflow-active").change(function() {
    if ($(this).val() == "1") {
      $('#edit-options').hide();
      $('#organizations').hide();      
    } else   
      if ($(this).val() == "2") {
      $('#edit-options').show();
      $('#organizations').hide();
    } else if ($(this).val() == "3") {
      $('#edit-options').hide();
      $('#organizations').show();
  } 
    else {
        $('#edit-options').hide();
        $('#organizations').hide();
    }
  });

  $(document).ready(function () {  
    var style = $("#field-approval-workflow-active").val();
    if (style == "1") {
      $('#edit-options').hide();
      $('#organizations').hide();
    } else if (style == "2") {
      $('#edit-options').show();
      $('#organizations').hide();
    } else if (style == "3") {
      $('#edit-options').hide();
      $('#organizations').show();
    }
  });