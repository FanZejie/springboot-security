package cn.fzj.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author Mike
 */
@Controller
public class RouterController {
    @RequestMapping({"/","/index"})
    public String index(){
        return "index";
    }
    @RequestMapping("/toLogin")
    public String toLogin(){
        return "views/login";
    }
    @RequestMapping("/level1/{id}")
    public String toLogin1(@PathVariable("id") int id){
        return "views/level1/"+id;
    }
    @RequestMapping("/level2/{id}")
    public String toLogin2(@PathVariable("id") int id){
        return "views/level2/"+id;
    }
    @RequestMapping("/level3/{id}")
    public String toLogin3(@PathVariable("id") int id){
        return "views/level3/"+id;
    }
}
