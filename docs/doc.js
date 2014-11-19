$(function() {
  var className = 'active';
  var topMenu = $("#toc");
  var menuItems = topMenu.find("a");
  var scrollItems = menuItems.map(function() {
    var item = $($(this).attr("href"));
    if (item.length) { return item; }
  });

  var lastTocScroll = 0;
  var lastTocScrollHuman = true;

  // Scroll an element so that it becomes visible
  // unless the user recently scrolled the toc div.
  // If the user scrolls to the top or the bottom of an overflow:scroll
  // element, the browser will scroll the main area, which will cause
  // another element to be activated (and scrolled to) in the toc pane.
  function scrollToView(pane, element) {
    if (new Date().getTime() - lastTocScroll < 2000) return;

    var y = element.position().top;
    if (y < 0 || y > pane.height()) {
      lastTocScrollHuman = false;
      pane.scrollTo(element, { axis: 'y' });
    }
  }

  topMenu.scroll(function() {
    if (lastTocScrollHuman) {
      lastTocScroll = new Date().getTime();
    } else {
      lastTocScrollHuman = true;
    }
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
   $('#toc a').removeClass(className);
   var item = menuItems.filter("[href=#"+id+"]");
   if (item.length != 0) {
     item.addClass(className);
     scrollToView(topMenu, item);
   }
 });
});
