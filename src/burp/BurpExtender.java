package burp;

import java.util.List;
import java.util.Collections;
import java.util.Arrays;
import java.net.URL;
import javax.swing.JMenuItem;
import javax.swing.AbstractAction;
import java.awt.event.ActionEvent;
import java.util.stream.Collectors;


public class BurpExtender implements IBurpExtender {

   private static IBurpExtenderCallbacks callbacks;
   private static IExtensionHelpers helpers;
   private String name;
   private String version;

   private static final class MenuOption implements IContextMenuFactory {

      private static final class MenuAction extends AbstractAction {

         IContextMenuInvocation invocation;

         public MenuAction(String name, IContextMenuInvocation invocation) {
            super(name);
            this.invocation = invocation;
         }

         @Override
         public void actionPerformed(ActionEvent e) {
            IContextMenuInvocation invocation = this.invocation;

            for (IHttpRequestResponse selected : invocation.getSelectedMessages()) {
               // TODO Not sure if the callbacks object is synchronized, I guess
               // I'll figure that out when the problem arises
               new Thread(new Runnable() {
                  public void run() {
                     IRequestInfo info = helpers.analyzeRequest(selected);
                     byte[] req = selected.getRequest();
                     List<String> headers = 
                        info.getHeaders().stream().map(h -> {
                           if (h.startsWith("Host")) {
                              return "Host: scriptalert.one";
                           } else {
                              return h;
                           }
                        }).collect(Collectors.toList());
                     byte[] body = Arrays.copyOfRange(req, info.getBodyOffset(), req.length);
                     byte[] newReq = helpers.buildHttpMessage(headers, body);
                     URL reqUrl = info.getUrl();
                     byte[] resp = callbacks.makeHttpRequest(reqUrl.getHost(), 
                           reqUrl.getPort(), reqUrl.getProtocol() == "https",
                           newReq);
                     if (helpers.indexOf(resp,
                                        helpers.stringToBytes("scriptalert.one"),
                                        false, 0, resp.length) > -1) {
                        callbacks.printOutput(helpers.bytesToString(resp));
                     }
                  }
               }).start();
            }
         }
      }

      @Override
      public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
         byte ivCtx = invocation.getInvocationContext();

         if (ivCtx == invocation.CONTEXT_TARGET_SITE_MAP_TABLE) {
            return Collections.singletonList(
                  new JMenuItem(
                     new MenuAction("Host Sweep", invocation)));
         }
         return null;
      }
   }

   @Override
   public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks) {
      this.callbacks = callbacks;
      this.helpers = callbacks.getHelpers();

      this.name = "Host Sweep";
      this.version = "0.0.1";

      callbacks.setExtensionName(this.name + " " + this.version);
      callbacks.registerContextMenuFactory(new MenuOption());
   }
}

