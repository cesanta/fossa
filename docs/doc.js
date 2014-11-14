$(function() {
  var className = 'active';
  var topMenu = $("#toc");
  var menuItems = topMenu.find("a");
  var scrollItems = menuItems.map(function() {
    var item = $($(this).attr("href"));
    if (item.length) { return item; }
  });

  $(window).scroll(function() {
    // Get container scroll position
   var fromTop = $(this).scrollTop() + 40;

   // Get id of current scroll item
   var cur = scrollItems.map(function(){
     if ($(this).offset().top < fromTop)
       return this;
   });
   // Get the id of the current element
   cur = cur[cur.length-1];
   var id = cur && cur.length ? cur[0].id : "";
   menuItems
     .parent().removeClass(className)
     .end().filter("[href=#"+id+"]").parent().addClass(className);
 });
});
