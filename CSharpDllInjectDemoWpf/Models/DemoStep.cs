using System.ComponentModel;

namespace CSharpDllInjectDemoWpf.Models
{
    public class DemoStep
    {
        public delegate void StepDelegate();

        public event PropertyChangedEventHandler? PropertyChanged;
        public StepDelegate? Step { get; private set; }
        public string? Code { get; set; }
        public string? Description { get; set; }
        public string? Hyperlink { get; set; }
        public bool NextExecutable
        {
            get => _nextExecutable;
            set
            {
                _nextExecutable = value;
                OnPropertyChanged(nameof(NextExecutable));  
            }
        }

        private bool _nextExecutable;

        public bool IsExecutable
        {
            get => Step != null;
        }        

        public DemoStep(StepDelegate? stepDelegate)
        {
            Step = stepDelegate;
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
