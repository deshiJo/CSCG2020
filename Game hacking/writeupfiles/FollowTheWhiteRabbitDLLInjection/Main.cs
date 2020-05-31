using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UnityEngine;
using UnityEngine.SceneManagement;

namespace followWhiteRabbit_hack
{
    class Main : MonoBehaviour
    {
        private const string ScenePath = @"C:\Users\Joachim\Desktop\CSCG\FollowWhiteRabbit\FollowWhiteRabbit_Data";
        private SceneLoader _sceneLoader;
        private PlayerController _playerC;

        public void Start()
        {
            _sceneLoader = FindObjectOfType<SceneLoader>();
            _playerC = FindObjectOfType<PlayerController>();
        }
        public void Update()
        {
            if (Input.GetKeyDown(KeyCode.F6))
            {
                _playerC.gravity = 0;
            }
            if (Input.GetKeyDown(KeyCode.F7))
            {
                GUI.Label(new Rect(Screen.width / 2, Screen.height / 2, 150f, 50f), "F6 pressed");
            }
            if (Input.GetKeyDown(KeyCode.F9))
            {
                AsyncOperation asyncLoad = SceneManager.LoadSceneAsync("FlagLand_Update", LoadSceneMode.Additive);
                asyncLoad.allowSceneActivation = true;
            }
            if (Input.GetKeyDown(KeyCode.F8))
            {
                AsyncOperation asyncLoad = SceneManager.LoadSceneAsync("level5");
                asyncLoad.allowSceneActivation = true;
            }
            if (Input.GetKeyDown(KeyCode.F10))
            {
                Scene scene = SceneManager.GetSceneByPath(ScenePath);
                GUI.Label(new Rect(Screen.width / 2, Screen.height / 2, 150f, 50f), scene.name);
            }
            if (Input.GetKeyDown(KeyCode.End)) // Will just unload our DLL
            {
                Loader.Unload();
            }
            sleep(5);
        }
        public void OnGUI()
        {

            GUI.Label(new Rect(Screen.width / 2, Screen.height / 2, 150f, 50f), "Success: GAME INJECTED"); 
            // Here you can call IMGUI functions of Unity to build your UI for the hack :)
        }
    }
}
